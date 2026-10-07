package ui

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	_ "embed"

	"github.com/example/warp-server/internal/access"
)

//go:embed static/index.html
var indexHTML []byte

type Server struct {
	apiBase string
	client  *http.Client
	tickets *ticketStore
	bg      *backgroundService
}

func New(apiBase string) *Server {
	return &Server{
		apiBase: strings.TrimRight(apiBase, "/"),
		client:  &http.Client{Timeout: 15 * time.Second},
		tickets: newTicketStore(),
		bg:      newBackgroundService(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /config-page", s.configPage)
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/config", s.config)
	mux.HandleFunc("GET /api/config-ticket", s.configTicket)
	mux.HandleFunc("GET /api/identities", s.identities)
	mux.HandleFunc("GET /api/endpoints", s.endpoints)
	mux.HandleFunc("GET /api/next-background", s.bg.nextBackground)
	return mux
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func isLocal(r *http.Request) bool {
	return access.IsTrusted(access.ClientIP(r))
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// get fetches a path from the API server and returns status and body.
func (s *Server) get(path string) (int, []byte, error) {
	resp, err := s.client.Get(s.apiBase + path)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

type counts struct {
	Endpoints      int `json:"endpoints"`
	EndpointsAlive int `json:"endpoints_alive"`
	Identities     int `json:"identities"`
}

// rttStats summarises the round trip times of the alive endpoints; it is an
// aggregate, so external clients see it too.
type rttStats struct {
	Best *int `json:"best,omitempty"`
	Avg  *int `json:"avg,omitempty"`
}

type stateResponse struct {
	Role           string          `json:"role"`
	Health         json.RawMessage `json:"health,omitempty"`
	Counts         counts          `json:"counts"`
	RTT            rttStats        `json:"rtt"`
	Identities     json.RawMessage `json:"identities,omitempty"`
	Endpoints      json.RawMessage `json:"endpoints,omitempty"`
	EndpointsAlive json.RawMessage `json:"endpoints_alive,omitempty"`
}

// state is the single call the web page makes. Local clients get the full
// service information, external clients only get counts, RTT statistics and
// health; the config itself is served separately by /api/config.
func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	healthCode, health, err := s.get("/health")
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "api unreachable")
		return
	}
	_, idBody, err := s.get("/api/identities")
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "api unreachable")
		return
	}
	_, epBody, err := s.get("/api/endpoints")
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "api unreachable")
		return
	}
	_, aliveBody, err := s.get("/api/endpoints?alive=true")
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "api unreachable")
		return
	}

	count := func(body []byte) int {
		var list []json.RawMessage
		if err := json.Unmarshal(body, &list); err != nil {
			return 0
		}
		return len(list)
	}

	resp := stateResponse{
		Role: "remote",
		Counts: counts{
			Endpoints:      count(epBody),
			EndpointsAlive: count(aliveBody),
			Identities:     count(idBody),
		},
		RTT: rttOf(aliveBody),
	}
	if healthCode == http.StatusOK {
		resp.Health = json.RawMessage(health)
	}

	if isLocal(r) {
		resp.Role = "local"
		resp.Identities = json.RawMessage(idBody)
		resp.Endpoints = json.RawMessage(epBody)
		resp.EndpointsAlive = json.RawMessage(aliveBody)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// rttOf returns the best and the average RTT of the given endpoints list
// (endpoints without a measurement are skipped).
func rttOf(body []byte) rttStats {
	var list []struct {
		RTT int `json:"RTT"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return rttStats{}
	}
	sum, n, best := 0, 0, 0
	for _, e := range list {
		if e.RTT <= 0 {
			continue
		}
		if n == 0 || e.RTT < best {
			best = e.RTT
		}
		sum += e.RTT
		n++
	}
	if n == 0 {
		return rttStats{}
	}
	avg := sum / n
	return rttStats{Best: &best, Avg: &avg}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.proxy(w, r, "/health", false)
}

func (s *Server) identities(w http.ResponseWriter, r *http.Request) {
	s.proxy(w, r, "/api/identities", true)
}

func (s *Server) endpoints(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("alive") == "true" {
		s.proxy(w, r, "/api/endpoints?alive=true", true)
		return
	}
	s.proxy(w, r, "/api/endpoints", true)
}

// proxy forwards a request to the API. localOnly endpoints (the full
// service data) are reserved for trusted clients; the API itself is already
// unreachable from outside, so the UI enforces the same policy.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request, path string, localOnly bool) {
	if localOnly && !isLocal(r) {
		writeJSONError(w, http.StatusForbidden, "local access only")
		return
	}

	code, body, err := s.get(path)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "api unreachable")
		return
	}
	if code == http.StatusForbidden {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	ct := "application/json"
	if strings.HasPrefix(path, "/config") {
		ct = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(code)
	w.Write(body)
}

// config serves the AmneziaWG configuration generated by the API.
//
//   - local (loopback / compose network) clients may fetch it directly;
//   - external clients must present a valid, fresh, IP-bound ticket issued
//     by /api/config-ticket, so the configuration is never reachable from
//     outside by a plain URL.
func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	if !isLocal(r) {
		if err := s.tickets.verify(r.URL.Query().Get("ticket"), access.ClientIP(r)); err != nil {
			writeJSONError(w, http.StatusForbidden, "valid ticket required")
			return
		}
	}
	s.serveConfig(w, r)
}

// configTicket issues the signed, timestamped ticket required by external
// clients to open the configuration page or fetch /api/config.
func (s *Server) configTicket(w http.ResponseWriter, r *http.Request) {
	token, err := s.tickets.issue(access.ClientIP(r))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "cannot issue ticket")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ticket":      token,
		"ttl_seconds": int(ticketTTL.Seconds()),
	})
}

// configPage renders the configuration page. Without a valid ticket the
// request is bounced back to the main page - a direct link never exposes
// the configuration block.
func (s *Server) configPage(w http.ResponseWriter, r *http.Request) {
	if err := s.tickets.verify(r.URL.Query().Get("ticket"), access.ClientIP(r)); err != nil {
		http.Redirect(w, r, "/?notice=link_expired", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func (s *Server) serveConfig(w http.ResponseWriter, r *http.Request) {
	code, body, err := s.get("/config")
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "api unreachable")
		return
	}
	if code != http.StatusOK {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="warp.conf"`)
	}
	w.Write(body)
}
