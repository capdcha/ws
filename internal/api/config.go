package api

import (
  "net/http"
  "github.com/example/warp-server/internal/db"
  "github.com/example/warp-server/internal/warp"
  "math/rand"
)

func ConfigHandler(database *db.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    identities, err := database.GetIdentities()
    if err != nil || len(identities) == 0 {
      http.Error(w, "No identities available", http.StatusServiceUnavailable)
      return
    }
    
    endpoints, err := database.GetAliveEndpoints(0.8)
    if err != nil || len(endpoints) == 0 {
      http.Error(w, "No endpoints available", http.StatusServiceUnavailable)
      return
    }
    
    identity := identities[rand.Intn(len(identities))]
    endpoint := endpoints[0]
    
    config := warp.GenerateAmneziaConfig(identity, endpoint)
    
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte(config))
  }
}
