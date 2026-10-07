package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Write([]byte(`{"status":"ok"}`))
		case "/api/identities":
			w.Write([]byte(`[{"ID":"a"},{"ID":"b"}]`))
		case "/api/endpoints":
			if r.URL.Query().Get("alive") == "true" {
				w.Write([]byte(`[{"ID":1,"RTT":12}]`))
			} else {
				w.Write([]byte(`[{"ID":1,"RTT":12},{"ID":2,"RTT":0},{"ID":3,"RTT":40}]`))
			}
		case "/config":
			w.Write([]byte("[Interface]\nPrivateKey = x\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, h http.Handler, path, addr string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = addr
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestStateRoles(t *testing.T) {
	api := fakeAPI(t)
	s := New(api.URL)
	routes := s.Routes()

	local := do(t, routes, "/api/state", "127.0.0.1:40000")
	if local.Code != http.StatusOK {
		t.Fatalf("local state status = %d", local.Code)
	}
	var full struct {
		Role   string         `json:"role"`
		Counts map[string]int `json:"counts"`
		RTT    struct {
			Best *int `json:"best"`
			Avg  *int `json:"avg"`
		} `json:"rtt"`
		Identities     []json.RawMessage `json:"identities"`
		Endpoints      []json.RawMessage `json:"endpoints"`
		EndpointsAlive []json.RawMessage `json:"endpoints_alive"`
	}
	if err := json.Unmarshal(local.Body.Bytes(), &full); err != nil {
		t.Fatalf("decode local state: %v", err)
	}
	if full.Role != "local" {
		t.Fatalf("role = %q, want local", full.Role)
	}
	if full.Counts["endpoints"] != 3 || full.Counts["endpoints_alive"] != 1 || full.Counts["identities"] != 2 {
		t.Fatalf("counts = %v", full.Counts)
	}
	if len(full.Identities) != 2 || len(full.Endpoints) != 3 || len(full.EndpointsAlive) != 1 {
		t.Fatalf("local state must contain full data: id=%d ep=%d alive=%d",
			len(full.Identities), len(full.Endpoints), len(full.EndpointsAlive))
	}
	if full.RTT.Best == nil || *full.RTT.Best != 12 || full.RTT.Avg == nil || *full.RTT.Avg != 12 {
		t.Fatalf("local rtt = %+v, want best=12 avg=12", full.RTT)
	}

	remote := do(t, routes, "/api/state", "203.0.113.9:40000")
	if remote.Code != http.StatusOK {
		t.Fatalf("remote state status = %d", remote.Code)
	}
	var limited struct {
		Role       string            `json:"role"`
		Counts     map[string]int    `json:"counts"`
		RTT        json.RawMessage   `json:"rtt"`
		Identities []json.RawMessage `json:"identities"`
		Endpoints  []json.RawMessage `json:"endpoints"`
		Health     json.RawMessage   `json:"health"`
	}
	if err := json.Unmarshal(remote.Body.Bytes(), &limited); err != nil {
		t.Fatalf("decode remote state: %v", err)
	}
	if limited.Role != "remote" {
		t.Fatalf("role = %q, want remote", limited.Role)
	}
	if limited.Counts["endpoints"] != 3 || limited.Counts["endpoints_alive"] != 1 || limited.Counts["identities"] != 2 {
		t.Fatalf("remote counts = %v", limited.Counts)
	}
	if len(limited.Identities) != 0 || len(limited.Endpoints) != 0 {
		t.Fatalf("remote state must not contain lists")
	}
	if string(limited.RTT) != `{"best":12,"avg":12}` {
		t.Fatalf("remote rtt must be visible as an aggregate: %s", limited.RTT)
	}
	if string(limited.Health) != `{"status":"ok"}` {
		t.Fatalf("remote health = %s", limited.Health)
	}
}

func TestDetailEndpointsAreLocalOnly(t *testing.T) {
	api := fakeAPI(t)
	s := New(api.URL)
	routes := s.Routes()

	for _, path := range []string{"/api/identities", "/api/endpoints", "/api/endpoints?alive=true"} {
		if w := do(t, routes, path, "127.0.0.1:40000"); w.Code != http.StatusOK {
			t.Errorf("local %s = %d, want 200", path, w.Code)
		}
		if w := do(t, routes, path, "198.51.100.4:40000"); w.Code != http.StatusForbidden {
			t.Errorf("remote %s = %d, want 403", path, w.Code)
		}
	}
}

// issueTicket fetches a ticket for addr through the UI routes.
func issueTicket(t *testing.T, routes http.Handler, addr string) string {
	t.Helper()
	w := do(t, routes, "/api/config-ticket", addr)
	if w.Code != http.StatusOK {
		t.Fatalf("config-ticket from %s = %d", addr, w.Code)
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode ticket: %v", err)
	}
	if body.Ticket == "" {
		t.Fatal("empty ticket")
	}
	return body.Ticket
}

// Local clients get the config directly; external clients must present a
// fresh ticket bound to their address. Without one the configuration is
// never reachable from outside.
func TestConfigGate(t *testing.T) {
	api := fakeAPI(t)
	s := New(api.URL)
	routes := s.Routes()

	if w := do(t, routes, "/api/config", "127.0.0.1:40000"); w.Code != http.StatusOK {
		t.Fatalf("local config = %d, want 200", w.Code)
	}
	if w := do(t, routes, "/api/config", "198.51.100.4:40000"); w.Code != http.StatusForbidden {
		t.Fatalf("remote config without ticket = %d, want 403", w.Code)
	}

	ticket := issueTicket(t, routes, "198.51.100.4:40000")
	w := do(t, routes, "/api/config?ticket="+ticket, "198.51.100.4:40000")
	if w.Code != http.StatusOK {
		t.Fatalf("remote config with ticket = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if strings.Contains(w.Body.String(), "{") {
		t.Fatalf("body looks like an error: %q", w.Body.String())
	}

	w = do(t, routes, "/api/config?download=1&ticket="+ticket, "198.51.100.4:40000")
	if cd := w.Header().Get("Content-Disposition"); cd != `attachment; filename="warp.conf"` {
		t.Fatalf("content-disposition = %q", cd)
	}

	// A ticket is bound to the address it was issued for.
	other := do(t, routes, "/api/config?ticket="+ticket, "203.0.113.9:40000")
	if other.Code != http.StatusForbidden {
		t.Fatalf("ticket from another address = %d, want 403", other.Code)
	}

	// Garbage tickets are rejected.
	for _, bad := range []string{"deadbeef", "aa.bb", ticket + "x"} {
		if w := do(t, routes, "/api/config?ticket="+bad, "198.51.100.4:40000"); w.Code != http.StatusForbidden {
			t.Fatalf("bad ticket %q = %d, want 403", bad, w.Code)
		}
	}
}

// The configuration page is never served by a plain (bookmarked or shared)
// link: without a valid ticket the visitor is bounced back to the main page.
func TestConfigPageRequiresTicket(t *testing.T) {
	api := fakeAPI(t)
	s := New(api.URL)
	routes := s.Routes()

	w := do(t, routes, "/config-page", "198.51.100.4:40000")
	if w.Code != http.StatusFound {
		t.Fatalf("/config-page without ticket = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/?notice=link_expired" {
		t.Fatalf("location = %q", loc)
	}

	ticket := issueTicket(t, routes, "198.51.100.4:40000")
	w = do(t, routes, "/config-page?ticket="+ticket, "198.51.100.4:40000")
	if w.Code != http.StatusOK {
		t.Fatalf("/config-page with ticket = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}

	w = do(t, routes, "/config-page?ticket="+ticket, "203.0.113.9:40000")
	if w.Code != http.StatusFound {
		t.Fatalf("/config-page ticket from another address = %d, want 302", w.Code)
	}
}
