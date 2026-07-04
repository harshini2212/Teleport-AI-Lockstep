#!/bin/bash
#
# harden.sh — idempotent macOS CIS-baseline hardening for managed fleet endpoints.
#
# This is the STANDALONE baseline: a root-run script that detects then applies a
# small, defensible set of CIS macOS Benchmark controls (FileVault, application
# firewall, Gatekeeper, screen-lock, automatic updates, guest account, SIP).
# Each control is detect-then-apply, so re-running converges rather than churns.
#
# THE ENFORCED PATH IS JAMF, NOT THIS SCRIPT. In a real fleet these controls are
# pushed and continuously re-asserted via Jamf Pro Configuration Profiles (and
# `softwareupdate`/Declarative Device Management for OS updates). A profile cannot
# be cleared by a local admin and is re-evaluated by the MDM framework; a shell
# script can be. Treat harden.sh as: (1) a readable, auditable statement of the
# baseline, (2) a Jamf policy script for hosts not yet under full profile
# management, and (3) the companion remediation to macos/compliance-check.sh,
# whose JSON the Teleport device-trust path consumes (see macos/README.md).
#
# Controls map to the CIS macOS Benchmark sections: 2.x (FileVault, firewall,
# Gatekeeper), 5.x (screen lock, guest), 1.x (software updates), and SIP (Apple
# system integrity protection, verified not toggled).
#
# Tested target: macOS 13–15 (Ventura/Sonoma/Sequoia). Some `defaults` domains and
# `socketfilterfw` flags are version-sensitive; comments flag where that bites.

set -euo pipefail
IFS=$'\n\t'

# --- guards -----------------------------------------------------------------

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: harden.sh must run as root (sudo). Refusing." >&2
    exit 1
  fi
}

log()  { printf '[harden] %s\n' "$*"; }
warn() { printf '[harden][WARN] %s\n' "$*" >&2; }

# CRITICAL: with `set -euo pipefail`, a `grep` that matches nothing exits 1 and
# aborts the whole script. Every status pipeline below is therefore guarded with
# `if ! cmd | grep -q ...; then` or terminated with `|| true` — never a bare
# `cmd | grep`. This helper centralises the safe "does the status say X?" check.
status_has() {
  # status_has "<producer cmd string>" "<grep pattern>"
  # Returns 0 if the pattern is present, 1 otherwise — and never trips pipefail.
  local out
  out="$(eval "$1" 2>/dev/null || true)"
  printf '%s' "$out" | grep -q "$2"
}

# --- controls ---------------------------------------------------------------

enable_filevault() {
  # CIS 2.6.x — full-disk encryption.
  #
  # HONESTY: FileVault cannot be silently force-enabled from a script. Turning it
  # on requires either an interactive user to authenticate, or a *deferred* enable
  # that fires at the next logout/login and hands the recovery key to the
  # institution. There is no `fdesetup enable` flag that encrypts a live disk with
  # no user interaction and no captured credentials. So this function:
  #   - reports current state, and
  #   - if off, arms the DEFERRED-ENABLE pattern (prompts the user at next logout,
  #     escrows an institutional recovery key to /var/db/.fvdefer.plist).
  # REAL enforcement is a Jamf "FileVault" Configuration Profile with a managed
  # Personal/Institutional recovery key and key escrow to Jamf — that is the path
  # the fleet uses; the line below is the standalone fallback.
  log "FileVault: checking current state via fdesetup status..."
  if status_has "fdesetup status" "FileVault is On"; then
    log "FileVault: already On — no action."
    return 0
  fi

  warn "FileVault: currently OFF. Arming deferred enable (user is prompted at next logout)."
  # -defer writes a plist that triggers the enable + recovery-key capture at the
  # next logout. We do NOT inline a recovery key here; escrow is the MDM's job.
  # `|| warn` so a host that can't arm deferral (e.g. already-encrypting) doesn't
  # abort the rest of the baseline.
  if fdesetup enable -defer /var/db/.fvdefer.plist >/dev/null 2>&1; then
    log "FileVault: deferred enable armed at /var/db/.fvdefer.plist."
  else
    warn "FileVault: could not arm deferred enable. Enforce via Jamf FileVault profile."
  fi
}

enable_firewall() {
  # CIS 2.x — application firewall + stealth mode.
  log "Firewall: enabling application firewall and stealth mode..."
  # These are idempotent: re-setting 'on' on an already-on firewall is a no-op.
  /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on   >/dev/null
  /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on   >/dev/null
  log "Firewall: global state on, stealth mode on."
}

enable_gatekeeper() {
  # CIS 2.x — Gatekeeper (only signed/notarised apps run by default).
  log "Gatekeeper: checking spctl status..."
  if status_has "spctl --status" "assessments enabled"; then
    log "Gatekeeper: already enabled — no action."
    return 0
  fi
  warn "Gatekeeper: disabled. Enabling assessments."
  # NOTE: on recent macOS `spctl --master-enable` is deprecated/removed in favour
  # of profile-managed Gatekeeper; it still works where present, hence the guard.
  spctl --master-enable >/dev/null 2>&1 || warn "Gatekeeper: spctl --master-enable unavailable; enforce via Jamf profile."
}

set_screensaver_lock() {
  # CIS 5.x — require password immediately after screensaver/sleep.
  log "Screen lock: requiring password immediately on screensaver/sleep..."
  # -currentHost because askForPassword* live in the ByHost domain. Idempotent.
  defaults -currentHost write com.apple.screensaver askForPassword -int 1
  defaults -currentHost write com.apple.screensaver askForPasswordDelay -int 0
  log "Screen lock: askForPassword=1, askForPasswordDelay=0."
}

enable_auto_updates() {
  # CIS 1.x — automatic check/download/install of OS and critical updates.
  log "Auto-updates: enabling scheduled software update + automatic install..."
  softwareupdate --schedule on >/dev/null 2>&1 || warn "Auto-updates: 'softwareupdate --schedule on' failed (continuing)."
  local dom="/Library/Preferences/com.apple.SoftwareUpdate"
  defaults write "$dom" AutomaticCheckEnabled            -bool true
  defaults write "$dom" AutomaticDownload                -bool true
  defaults write "$dom" AutomaticallyInstallMacOSUpdates -bool true
  defaults write "$dom" CriticalUpdateInstall            -bool true
  log "Auto-updates: check/download/macOS-install/critical-install all true."
}

disable_guest() {
  # CIS 5.x — no guest account.
  log "Guest account: disabling..."
  sysadminctl -guestAccount off >/dev/null 2>&1 || warn "Guest account: sysadminctl call failed (continuing)."
  defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
  log "Guest account: disabled (sysadminctl + loginwindow GuestEnabled=false)."
}

verify_sip() {
  # System Integrity Protection — VERIFY ONLY.
  # SIP cannot be toggled from a booted system; `csrutil enable/disable` only works
  # from the Recovery environment. So we report and fail loud if it is off, since a
  # SIP-disabled host should not pass the baseline.
  log "SIP: verifying System Integrity Protection (csrutil status)..."
  if status_has "csrutil status" "enabled"; then
    log "SIP: enabled."
  else
    warn "SIP: NOT enabled. SIP can only be re-enabled from Recovery (csrutil enable)."
    warn "SIP: flagging non-compliant — re-image or re-enable from Recovery before trusting this host."
  fi
}

# --- main -------------------------------------------------------------------

main() {
  require_root
  log "Starting macOS CIS baseline hardening (standalone; Jamf profiles are the enforced path)."
  enable_filevault
  enable_firewall
  enable_gatekeeper
  set_screensaver_lock
  enable_auto_updates
  disable_guest
  verify_sip
  log "Baseline pass complete. Run macos/compliance-check.sh to audit the result."
}

main "$@"
