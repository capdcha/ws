package db

import (
  "database/sql"
  "embed"
  "fmt"
  "os"
  "strconv"
  "time"
  _ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

// DefaultMaxEndpoints caps how many endpoints can ever exist in the table.
const DefaultMaxEndpoints = 1000

type DB struct {
  conn *sql.DB
  maxEndpoints int
}

func maxEndpointsFromEnv() int {
  if v := os.Getenv("MAX_ENDPOINTS"); v != "" {
    if n, err := strconv.Atoi(v); err == nil && n > 0 {
      return n
    }
  }
  return DefaultMaxEndpoints
}

func New(path string) (*DB, error) {
  conn, err := sql.Open("sqlite", path)
  if err != nil {
    return nil, err
  }

  conn.Exec("PRAGMA journal_mode=WAL")

  schemaBytes, err := schemaFS.ReadFile("schema.sql")
  if err != nil {
    conn.Close()
    return nil, fmt.Errorf("reading schema.sql: %w", err)
  }

  for i := 0; i < 10; i++ {
    _, err = conn.Exec(string(schemaBytes))
    if err == nil {
      return &DB{conn: conn, maxEndpoints: maxEndpointsFromEnv()}, nil
    }
    time.Sleep(200 * time.Millisecond)
  }
  conn.Close()
  return nil, fmt.Errorf("applying schema after retries: %w", err)
}

func (db *DB) Close() error {
  return db.conn.Close()
}
