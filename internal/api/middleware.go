package api

import (
	"log"
	"net/http"

	"github.com/example/warp-server/internal/access"
)

// RestrictAPI denies every request that does not come from a trusted
// (local) address. Only loopback clients - and the compose network used by
// the UI proxy - may talk to the API port directly.
func RestrictAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := access.ClientIP(r)
		if !access.IsTrusted(ip) {
			log.Printf("api: denied %s %s from %s", r.Method, r.URL.Path, ip)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden","reason":"non-local address"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
