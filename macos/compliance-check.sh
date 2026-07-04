#!/bin/bash
#
# compliance-check.sh — read-only macOS posture auditor.
#
# Emits a SINGLE strict JSON object describing the host's compliance with the
# baseline that macos/harden.sh applies. Read-only: it never changes state, so it
# is safe to run from a Jamf Extension Attribute on every inventory check-in.
#
# The JSON is the contract between the endpoint and the Teleport device-trust
# path. It is consumed two ways:
#   1. Directly as a Jamf Extension Attribute (with --jamf-ea, the object is
#      wrapped in <result>...</result> as Jamf requires).
#   2. By the Go side (go/internal/jamf), unmarshalled into:
#         type Compliance struct {
#           FileVault     bool `json:"filevault"`
#           Firewall      bool `json:"firewall"`
#           Gatekeeper    bool `json:"gatekeeper"`
#           SIP           bool `json:"sip"`
#           ScreenLock    bool `json:"screen_lock"`
#           AutoUpdates   bool `json:"auto_updates"`
#           GuestDisabled bool `json:"guest_disabled"`
#           Overall       bool `json:"overall"`
#         }
#      plus a top-level "serial" string.
#
# Keys are EXACTLY: serial, filevault, firewall, gatekeeper, sip, screen_lock,
# auto_updates, guest_disabled, overall. Booleans are emitted as bare true/false.
# No jq dependency — the object is assembled with printf so it runs on a stock
# macOS box with nothing installed.

set -euo pipefail
IFS=$'\n\t'

# --- safe status helper -----------------------------------------------------
# With `set -euo pipefail` a grep that matches nothing exits 1 and would abort the
# audit. Every probe routes through here, which captures output defensively and
# returns a clean 0/1 — never tripping pipefail on a bare `cmd | grep`.
status_has() {
  # status_has "<producer cmd string>" "<grep pattern>"
  local out
  out="$(eval "$1" 2>/dev/null || true)"
  printf '%s' "$out" | grep -q "$2"
}

# Translate a 0/1 shell result into the JSON literals true/false.
as_bool() { if "$@"; then printf 'true'; else printf 'false'; fi; }

# --- probes (all read-only) -------------------------------------------------

probe_serial() {
  # Hardware serial; the join key against Jamf inventory and Teleport device IDs.
  # Trailing `|| true`: `head` closes the pipe early, so ioreg can take SIGPIPE
  # (141); without the guard, pipefail would abort the whole script and emit no
  # JSON. This must never fail — the JSON contract depends on it.
  ioreg -l 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4}' | head -n1 || true
}

probe_filevault()   { status_has "fdesetup status"     "FileVault is On"; }
probe_firewall()    { status_has "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate" "enabled"; }
probe_gatekeeper()  { status_has "spctl --status"      "assessments enabled"; }
probe_sip()         { status_has "csrutil status"      "enabled"; }

probe_screen_lock() {
  # Compliant iff askForPassword=1 AND askForPasswordDelay=0 (lock immediately).
  # `defaults read` errors (and exits 1) if the key is unset, so swallow with ||.
  local ask delay
  ask="$(defaults -currentHost read com.apple.screensaver askForPassword 2>/dev/null || echo 0)"
  delay="$(defaults -currentHost read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo 999)"
  [ "$ask" = "1" ] && [ "$delay" = "0" ]
}

probe_auto_updates() {
  # Require automatic check + download enabled at minimum.
  local dom="/Library/Preferences/com.apple.SoftwareUpdate" chk dl
  chk="$(defaults read "$dom" AutomaticCheckEnabled 2>/dev/null || echo 0)"
  dl="$(defaults read "$dom" AutomaticDownload 2>/dev/null || echo 0)"
  [ "$chk" = "1" ] && [ "$dl" = "1" ]
}

probe_guest_disabled() {
  # Compliant when the guest account is OFF. GuestEnabled defaults to true if the
  # key is absent on some releases, so absence is treated as NOT disabled.
  local g
  g="$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo 1)"
  [ "$g" = "0" ]
}

# --- assemble JSON ----------------------------------------------------------

main() {
  local jamf_ea=0
  for arg in "$@"; do
    case "$arg" in
      --jamf-ea) jamf_ea=1 ;;
      *) printf 'unknown flag: %s\n' "$arg" >&2; exit 2 ;;
    esac
  done

  local serial filevault firewall gatekeeper sip screen_lock auto_updates guest_disabled
  serial="$(probe_serial)"
  filevault="$(as_bool probe_filevault)"
  firewall="$(as_bool probe_firewall)"
  gatekeeper="$(as_bool probe_gatekeeper)"
  sip="$(as_bool probe_sip)"
  screen_lock="$(as_bool probe_screen_lock)"
  auto_updates="$(as_bool probe_auto_updates)"
  guest_disabled="$(as_bool probe_guest_disabled)"

  # overall is true only if every required control passes. Kept as a shell
  # conjunction so the policy ("which controls are required") is explicit here and
  # not re-derived by the consumer.
  local overall="false"
  if [ "$filevault" = "true" ] && [ "$firewall" = "true" ] && [ "$gatekeeper" = "true" ] \
     && [ "$sip" = "true" ] && [ "$screen_lock" = "true" ] && [ "$auto_updates" = "true" ] \
     && [ "$guest_disabled" = "true" ]; then
    overall="true"
  fi

  # printf, not jq: the serial is the only string (quoted); the rest are bare
  # JSON booleans. %s on already-validated true/false keeps the object strict.
  local json
  json="$(printf '{"serial":"%s","filevault":%s,"firewall":%s,"gatekeeper":%s,"sip":%s,"screen_lock":%s,"auto_updates":%s,"guest_disabled":%s,"overall":%s}' \
    "$serial" "$filevault" "$firewall" "$gatekeeper" "$sip" "$screen_lock" "$auto_updates" "$guest_disabled" "$overall")"

  if [ "$jamf_ea" -eq 1 ]; then
    # Jamf Extension Attribute contract: stdout must be <result>VALUE</result>.
    printf '<result>%s</result>\n' "$json"
  else
    printf '%s\n' "$json"
  fi
}

main "$@"
