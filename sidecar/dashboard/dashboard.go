// Package dashboard provides an optional web UI for the cloudflared
// sidecar. It embeds zero third-party dependencies — all pages are
// rendered with html/template and served over a plain net/http server.
//
// Intended for use during development, monitoring by a SkyNet runtime
// operator, or ad-hoc debugging. The dashboard listens on a
// user-configurable address only if dashboard_addr is set; it is
// disabled by default so the sidecar stays minimal.
//
// Routes:
//
//	GET  /              HTML status page
//	GET  /api/status    JSON snapshot of component + backends
//	POST /api/start     start the component (if not running)
//	POST /api/stop      stop the component (if running)
//	GET  /api/logs      JSON array of recent log lines
package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

// Component is the minimal contract we require from the sidecar
// component. It mirrors the IComponent + Backend surface we need
// for display purposes.
type Component interface {
	Name() string
	State() string
	BackendType() string
	BackendName() string
	RecentLines(n int) []string
}

// Backend exposes the backend snapshot interface used for rendering.
type Backend interface {
	Name() string
	Type() string
}

// Server wraps an http.Server along with the component so the
// dashboard can render its state.
type Server struct {
	addr      string
	component Component

	server *http.Server
	done   chan struct{}
}

// NewServer creates a dashboard server. A zero address disables the
// server (it won't be started) — callers should check IsEnabled().
func NewServer(addr string, comp Component) *Server {
	return &Server{addr: addr, component: comp, done: make(chan struct{})}
}

// IsEnabled reports whether the server has an address and will serve
// on Start().
func (s *Server) IsEnabled() bool { return s.addr != "" && s.addr != "0" && s.addr != "off" }

// Start binds and serves. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if !s.IsEnabled() {
		<-ctx.Done()
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/api/status", s.statusHandler)
	mux.HandleFunc("/api/start", s.startHandler)
	mux.HandleFunc("/api/stop", s.stopHandler)
	mux.HandleFunc("/api/logs", s.logsHandler)

	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		err := s.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			// Best-effort: log via stderr via fmt.
			fmt.Printf("[dashboard] server error: %v\n", err)
		}
		close(s.done)
	}()
	<-ctx.Done()

	// Graceful shutdown.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.server.Shutdown(shutdownCtx)
	<-s.done
	return nil
}

// ---- Handlers -------------------------------------------------------------

func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"name":      s.component.Name(),
		"state":     s.component.State(),
		"backend":   s.component.BackendType(),
		"backend_name": s.component.BackendName(),
		"lines":     s.component.RecentLines(32),
		"now":       time.Now().UTC().Format(time.RFC3339),
	}
	if err := indexTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":        s.component.Name(),
		"state":       s.component.State(),
		"backend":     s.component.BackendType(),
		"backend_name": s.component.BackendName(),
		"recent_logs": s.component.RecentLines(32),
	})
}

func (s *Server) startHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Start is implemented by the caller; we provide a placeholder
	// that says OK — the sidecar uses the IPC bus to trigger start
	// externally. This hook lets future work wire up an internal
	// start command.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "start requested — see SkyNet runtime"})
}

func (s *Server) stopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "stop requested — see SkyNet runtime"})
}

func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"lines": s.component.RecentLines(100)})
}

// ---- Templates ------------------------------------------------------------

// indexTmpl is the HTML for the root dashboard page. Kept inline so we
// have zero template files to ship.
var indexTmpl = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cloudflared Sidecar: {{.name}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:24px;color:#222;background:#fafafa}
.card{background:#fff;padding:16px 24px;border:1px solid #ddd;border-radius:8px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
h1{margin:0 0 8px;font-size:20px}
h2{margin:0 0 12px;font-size:16px}
pre{background:#111;color:#eee;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600;letter-spacing:.5px}
.ok{background:#d4edda;color:#155724}
.err{background:#f8d7da;color:#721c24}
.other{background:#e2e3e5;color:#383d41}
.row{display:flex;gap:16px;align-items:center;margin-bottom:8px}
.meta{color:#666;font-size:12px}
</style>
</head>
<body>
<div class="card">
<h1>{{.name}} <span class="badge {{if eq .state "RUNNING"}}ok{{else}}other{{end}}">{{.state}}</span></h1>
<div class="row"><span class="meta">Backend:</span> <code>{{.backend}}</code></div>
<div class="row"><span class="meta">Origin:</span> <code>{{.backend_name}}</code></div>
<div class="row"><span class="meta">Snapshot time:</span> <code>{{.now}} UTC</code></div>
</div>
<div class="card">
<h2>Recent logs</h2>
<pre>{{range .lines}}{{.}}
{{end}}</pre>
</div>
<div class="card">
<h2>HTTP API</h2>
<pre>GET  /api/status  → JSON snapshot
POST /api/start    → request start (via SkyNet runtime)
POST /api/stop     → request stop (via SkyNet runtime)
GET  /api/logs     → recent log lines</pre>
</div>
</body>
</html>`))
