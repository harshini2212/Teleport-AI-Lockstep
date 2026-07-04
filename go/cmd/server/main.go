// Command server is the live Lifecycle Guard backend. It serves the dashboard
// and a JSON API over the same in-memory engine the CLI uses, so the dashboard
// is a real full-stack app on localhost — not a static file.
//
//	cd go && go run ./cmd/server            # http://localhost:8080
//	go run ./cmd/server -addr :9000 -dashboard ../dashboard
//
// API:
//	GET  /api/healthz        liveness
//	GET  /api/trace          current run (steps, agents, jit, findings, devices, state)
//	POST /api/reset          reload the built-in demo, return the fresh trace
//	POST /api/human-event    {type,id,email,name,department,title,prior_department} -> {actions,trace}
//	POST /api/agent-event    {type,name,scope[],prior_scope[]} -> {actions,trace}
//	POST /api/jit            {user,requested} -> {decision,trace}
//	POST /api/review         run the LLM access-review copilot -> {enabled,review|message}
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/copilot"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/scenario"
)

func main() {
	addr := flag.String("addr", "", "listen address (default: $PORT if set, else :8080)")
	dashboard := flag.String("dashboard", "../dashboard", "path to the dashboard directory")
	envFile := flag.String("env", "", "path to a .env file (default: try .env then ../.env)")
	flag.Parse()

	// Load KEY=VALUE lines from a .env file so ANTHROPIC_API_KEY can live in a
	// git-ignored file instead of the shell. Real environment variables win.
	if *envFile != "" {
		loadDotEnv(*envFile)
	} else {
		loadDotEnv(".env", "../.env")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		log.Print("ANTHROPIC_API_KEY detected — access-review copilot enabled")
	} else {
		log.Print("no ANTHROPIC_API_KEY — access-review copilot runs in disabled mode")
	}

	run := scenario.New()
	srv := &api{run: run}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", srv.healthz)
	mux.HandleFunc("/api/trace", srv.trace)
	mux.HandleFunc("/api/scenarios", srv.scenarios)
	mux.HandleFunc("/api/scenario", srv.loadScenario)
	mux.HandleFunc("/api/reset", srv.reset)
	mux.HandleFunc("/api/human-event", srv.humanEvent)
	mux.HandleFunc("/api/agent-event", srv.agentEvent)
	mux.HandleFunc("/api/jit", srv.jit)
	mux.HandleFunc("/api/review", srv.review)
	mux.HandleFunc("/api/ask", srv.ask)
	mux.HandleFunc("/api/lock", srv.lock)
	mux.HandleFunc("/api/terminate-session", srv.terminate)
	mux.HandleFunc("/api/device", srv.device)
	mux.HandleFunc("/api/incident", srv.incident)
	mux.Handle("/", http.FileServer(http.Dir(*dashboard)))

	// Resolve the listen address: an explicit -addr always wins; otherwise honor
	// $PORT (Railway and most PaaS inject a dynamic port here) and fall back to
	// :8080 for local runs. Binding ":port" listens on all interfaces (0.0.0.0),
	// which the platform health-check requires.
	listen := *addr
	if listen == "" {
		if p := os.Getenv("PORT"); p != "" {
			listen = ":" + p
		} else {
			listen = ":8080"
		}
	}

	log.Printf("Lifecycle Guard backend listening on http://localhost%s  (dashboard: %s)", listen, *dashboard)
	log.Fatal(http.ListenAndServe(listen, withLog(mux)))
}

// loadDotEnv reads the first readable path and sets any KEY=VALUE lines into the
// process environment, without overriding variables already set. Best effort:
// a missing file is fine.
func loadDotEnv(paths ...string) {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		n := 0
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq < 0 {
				continue
			}
			key := strings.TrimSpace(line[:eq])
			val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
			if key != "" && os.Getenv(key) == "" {
				_ = os.Setenv(key, val)
				n++
			}
		}
		f.Close()
		log.Printf("loaded %d var(s) from %s", n, p)
		return
	}
}

type api struct{ run *scenario.Runner }

func (a *api) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "lifecycle-guard"})
}

func (a *api) trace(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.run.Trace())
}

func (a *api) scenarios(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, scenario.Scenarios())
}

func (a *api) loadScenario(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.run.Load(req.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, a.run.Trace())
}

func (a *api) reset(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	a.run.Seed()
	writeJSON(w, http.StatusOK, a.run.Trace())
}

type humanReq struct {
	Type            string `json:"type"`
	ID              string `json:"id"`
	Email           string `json:"email"`
	Name            string `json:"name"`
	Department      string `json:"department"`
	Title           string `json:"title"`
	PriorDepartment string `json:"prior_department"`
}

func (a *api) humanEvent(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req humanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ev := scenario.NewHumanEvent(req.Type, req.ID, req.Email, req.Name, req.Department, req.Title, req.PriorDepartment, time.Now())
	actions, err := a.run.ApplyHuman(ev)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions, "trace": a.run.Trace()})
}

type agentReq struct {
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	Scope     []string `json:"scope"`
	PriorScope []string `json:"prior_scope"`
}

func (a *api) agentEvent(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req agentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ev := scenario.NewAgentEvent(req.Type, req.Name, req.Scope, req.PriorScope, time.Now())
	actions, err := a.run.ApplyAgent(ev)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions, "trace": a.run.Trace()})
}

func (a *api) jit(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req engine.AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	d, err := a.run.JIT(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"decision": d, "trace": a.run.Trace()})
}

func (a *api) review(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	c, err := copilot.NewClient()
	if err == copilot.ErrNoAPIKey {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"message": "Set ANTHROPIC_API_KEY on the server to enable the LLM access review.",
		})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	tr := a.run.Trace()
	ev := copilot.BuildEvidence("2026-Q2", policy.Default(), tr.Findings,
		tr.FinalState.Users, tr.FinalState.Locks, tr.FinalState.Sessions, tr.JITDecisions)
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	rev, err := copilot.Generate(ctx, c, ev)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "review": rev})
}

func (a *api) ask(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Question string `json:"question"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	c, err := copilot.NewClient()
	if err == copilot.ErrNoAPIKey {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"message": "Set ANTHROPIC_API_KEY on the server to enable the AI assistant.",
		})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	tr := a.run.Trace()
	ev := copilot.BuildEvidence("current", policy.Default(), tr.Findings,
		tr.FinalState.Users, tr.FinalState.Locks, tr.FinalState.Sessions, tr.JITDecisions)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	answer, err := copilot.Ask(ctx, c, ev, req.Question)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "answer": answer})
}

func (a *api) lock(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Reason == "" {
		req.Reason = "manual lock via console"
	}
	actions, err := a.run.Lock(req.Target, req.Reason)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions, "trace": a.run.Trace()})
}

func (a *api) terminate(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		User string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	actions, err := a.run.TerminateSessions(req.User)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions, "trace": a.run.Trace()})
}

func (a *api) device(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Email     string `json:"email"`
		Serial    string `json:"serial"`
		Managed   bool   `json:"managed"`
		Compliant bool   `json:"compliant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	actions, err := a.run.UpsertDevice(req.Email, req.Serial, req.Managed, req.Compliant)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions, "trace": a.run.Trace()})
}

func (a *api) incident(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	actions, err := a.run.Incident(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions, "trace": a.run.Trace()})
}

// --- helpers ---

func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errString("POST required"))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

type errString string

func (e errString) Error() string { return string(e) }

func withLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
