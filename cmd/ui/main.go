package main

import (
	"github.com/example/warp-server/internal/ui"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("UI_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	apiBase := os.Getenv("API_ADDR")
	if apiBase == "" {
		apiBase = "http://localhost:8080"
	}

	srv := ui.New(apiBase)
	log.Printf("UI listening on %s (api: %s)", addr, apiBase)
	log.Fatal(http.ListenAndServe(addr, srv.Routes()))
}
