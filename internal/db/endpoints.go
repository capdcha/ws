package db

import (
  "errors"
  "github.com/example/warp-server/internal/scanner"
  "time"
)

// ErrEndpointLimitReached is returned when inserting a new endpoint would
// push the table past the configured maximum. Updates of existing rows are
// never blocked.
var ErrEndpointLimitReached = errors.New("endpoint limit reached")

func (db *DB) UpsertEndpoint(e *scanner.Endpoint) error {
  tx, err := db.conn.Begin()
  if err != nil {
    return err
  }
  defer tx.Rollback()

  var exists int
  if err := tx.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE host = ? AND port = ?`,
    e.Host, e.Port).Scan(&exists); err != nil {
    return err
  }

  if exists == 0 {
    var total int
    if err := tx.QueryRow(`SELECT COUNT(*) FROM endpoints`).Scan(&total); err != nil {
      return err
    }
    if total >= db.maxEndpoints {
      return ErrEndpointLimitReached
    }
  }

  if _, err := tx.Exec(`
    INSERT INTO endpoints (host, port, rtt_ms, last_seen)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(host, port) DO UPDATE SET
      rtt_ms = excluded.rtt_ms,
      last_seen = excluded.last_seen`,
    e.Host, e.Port, e.RTT, nowSQL(),
  ); err != nil {
    return err
  }

  return tx.Commit()
}

func (db *DB) GetAllEndpoints() ([]*scanner.Endpoint, error) {
  rows, err := db.conn.Query(`
    SELECT id, host, port, rtt_ms FROM endpoints
    ORDER BY rtt_ms ASC`)
  if err != nil {
    return nil, err
  }
  defer rows.Close()

  result := []*scanner.Endpoint{}
  for rows.Next() {
    var e scanner.Endpoint
    rows.Scan(&e.ID, &e.Host, &e.Port, &e.RTT)
    result = append(result, &e)
  }
  return result, nil
}

func (db *DB) GetAliveEndpoints(minSuccessRate float64) ([]*scanner.Endpoint, error) {
  rows, err := db.conn.Query(`
    SELECT id, host, port, rtt_ms FROM endpoints
    WHERE datetime(last_seen) > datetime('now', '-1 hour')
      AND (success_count + fail_count = 0
           OR (success_count * 1.0) / (success_count + fail_count) >= ?)
    ORDER BY rtt_ms ASC`,
    minSuccessRate,
  )
  if err != nil {
    return nil, err
  }
  defer rows.Close()

  result := []*scanner.Endpoint{}
  for rows.Next() {
    var e scanner.Endpoint
    rows.Scan(&e.ID, &e.Host, &e.Port, &e.RTT)
    result = append(result, &e)
  }
  return result, nil
}

func (db *DB) UpdateEndpointMetrics(id int64, rtt int, success bool) error {
  var query string
  var args []interface{}

  if success {
    query = "UPDATE endpoints SET rtt_ms = ?, success_count = success_count + 1, last_checked = ? WHERE id = ?"
    args = []interface{}{rtt, nowSQL(), id}
  } else {
    query = "UPDATE endpoints SET fail_count = fail_count + 1, last_checked = ? WHERE id = ?"
    args = []interface{}{nowSQL(), id}
  }

  _, err := db.conn.Exec(query, args...)
  return err
}

// nowSQL returns the current time formatted so SQLite's datetime() and
// strftime() can parse it (datetime('now') format in UTC). time.Now()'s raw
// String() form (with " +0000 UTC" and a monotonic clock suffix) is not
// understood by SQLite's datetime() and would silently break time-range
// comparisons.
func nowSQL() string {
  return time.Now().UTC().Format("2006-01-02 15:04:05")
}
