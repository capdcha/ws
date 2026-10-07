package main

import (
  "context"
  "errors"
  "log"
  "os"
  "time"
  "github.com/example/warp-server/internal/db"
  "github.com/example/warp-server/internal/warp"
  "github.com/example/warp-server/internal/scanner"
)

func main() {
  if len(os.Args) < 2 {
    log.Fatal("Usage: worker <register|scan|probe>")
  }
  
  cmd := os.Args[1]
  ctx := context.Background()
  
  dbPath := os.Getenv("DB_PATH")
  if dbPath == "" {
    dbPath = "warp.db"
  }
  database, err := db.New(dbPath)
  if err != nil {
    log.Fatalf("Failed to open DB: %v", err)
  }
  defer database.Close()
  
  switch cmd {
  case "register":
    log.Println("Starting register worker")
    MaintainIdentityPool(ctx, database, 10, 5*time.Minute)
  case "scan":
    log.Println("Starting scan worker")
    ScanPeriodically(ctx, database, 10*time.Minute)
  case "probe":
    log.Println("Starting probe worker")
    ProbeEndpointsPeriodically(ctx, database, 2*time.Minute)
  default:
    log.Fatalf("Unknown command: %s", cmd)
  }
}

func MaintainIdentityPool(ctx context.Context, database *db.DB, targetCount int, interval time.Duration) {
  run := func() {
    identities, _ := database.GetIdentities()
    if len(identities) < targetCount {
      log.Printf("Registering new identity (%d/%d)", len(identities), targetCount)
      
      identity, err := warp.RegisterIdentity(ctx)
      if err != nil {
        log.Printf("Registration failed: %v", err)
        return
      }
      
      if err := database.InsertIdentity(identity); err != nil {
        log.Printf("Failed to save identity: %v", err)
      } else {
        log.Printf("Identity registered: %s", identity.ID)
      }
    }
  }

  run()

  ticker := time.NewTicker(interval)
  defer ticker.Stop()
  
  for {
    select {
    case <-ctx.Done():
      return
    case <-ticker.C:
      run()
    }
  }
}

func ScanPeriodically(ctx context.Context, database *db.DB, interval time.Duration) {
  run := func() {
    log.Println("Starting endpoint scan")

    scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
    defer cancel()

    identities, _ := database.GetIdentities()
    if len(identities) == 0 {
      log.Println("No identity available for scanning, skipping")
      return
    }
    identity := identities[0]

    prefixes := warp.WarpPrefixes()
    ports := warp.WarpPorts()

    keys := &scanner.IdentityKeys{
      PrivateKey:    identity.PrivateKey,
      PublicKey:     identity.PublicKey,
      PeerPublicKey: identity.PeerPublicKey,
    }

    endpoints, err := scanner.ScanEndpoints(scanCtx, prefixes, ports, 50, keys)
    if err != nil {
      log.Printf("Scan failed: %v", err)
      return
    }

    for _, ep := range endpoints {
      if err := database.UpsertEndpoint(&ep); err != nil {
        if errors.Is(err, db.ErrEndpointLimitReached) {
          log.Printf("Endpoint limit (%d) reached, skipping remaining scan results", db.DefaultMaxEndpoints)
          break
        }
        log.Printf("Failed to save endpoint: %v", err)
      }
    }

    log.Printf("Scan complete: %d endpoints found", len(endpoints))
  }

  run()

  ticker := time.NewTicker(interval)
  defer ticker.Stop()
  
  for {
    select {
    case <-ctx.Done():
      return
    case <-ticker.C:
      run()
    }
  }
}

func ProbeEndpointsPeriodically(ctx context.Context, database *db.DB, interval time.Duration) {
  run := func() {
    log.Println("Starting endpoint probing")
    
    endpoints, _ := database.GetAliveEndpoints(0.5)
    identities, _ := database.GetIdentities()
    
    if len(identities) == 0 {
      log.Println("No identities available for probing")
      return
    }
    
    identity := identities[0]
    keys := &scanner.IdentityKeys{
      PrivateKey:    identity.PrivateKey,
      PublicKey:     identity.PublicKey,
      PeerPublicKey: identity.PeerPublicKey,
    }
    
    for _, ep := range endpoints {
      rtt, err := scanner.ProbeEndpoint(ctx, *ep, keys)
      success := err == nil

      if err := database.UpdateEndpointMetrics(ep.ID, rtt, success); err != nil {
        log.Printf("Failed to update metrics for %s:%d: %v", ep.Host, ep.Port, err)
      }

      if success {
        log.Printf("Probed %s:%d - RTT %dms", ep.Host, ep.Port, rtt)
      }
    }
  }

  run()

  ticker := time.NewTicker(interval)
  defer ticker.Stop()
  
  for {
    select {
    case <-ctx.Done():
      return
    case <-ticker.C:
      run()
    }
  }
}
