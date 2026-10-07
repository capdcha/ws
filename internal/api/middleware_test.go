package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// trustedSubnetSample returns an address from the container's own subnet,
// i.e. the source address docker-proxy uses for host connections.
func trustedSubnetSample(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
				continue
			}
			return ipn.IP.String()
		}
	}
	return ""
}

func TestRestrictAPI(t *testing.T) {
	h := RestrictAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	cases := []struct {
		name string
		addr string
		want int
	}{
		{"loopback v4", "127.0.0.1:51000", http.StatusOK},
		{"loopback v6", "[::1]:51000", http.StatusOK},
		{"internet client", "203.0.113.7:51000", http.StatusForbidden},
		{"lan client", "192.168.1.50:51000", http.StatusForbidden},
		{"empty addr", "", http.StatusForbidden},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/health", nil)
			r.RemoteAddr = c.addr
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d", w.Code, c.want)
			}
			if c.want == http.StatusForbidden && w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("forbidden response must be json, got %q", w.Header().Get("Content-Type"))
			}
		})
	}
}

// Requests originating from the compose network (the UI proxy) must pass.
func TestRestrictAPITrustedSubnet(t *testing.T) {
	ip := trustedSubnetSample(t)
	if ip == "" {
		t.Skip("no non-loopback interface available")
	}

	h := RestrictAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("GET", "/config", nil)
	r.RemoteAddr = ip + ":51000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status from trusted subnet %s = %d, want 200", ip, w.Code)
	}
}
