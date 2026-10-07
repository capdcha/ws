package main

import (
  "log"
  "net/http"
  "os"
  "github.com/example/warp-server/internal/api"
  "github.com/example/warp-server/internal/db"
)

func main() {
  dbPath := os.Getenv("DB_PATH")
  if dbPath == "" {
    dbPath = "warp.db"
  }
  database, err := db.New(dbPath)
  if err != nil {
    log.Fatal(err)
  }
  defer database.Close()
  
  router := api.NewRouter(database)
  log.Println("Server listening on :8080")
  http.ListenAndServe(":8080", router)
}
