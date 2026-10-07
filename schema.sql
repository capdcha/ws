CREATE TABLE IF NOT EXISTS identities (
  id TEXT PRIMARY KEY,
  private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  client_id TEXT NOT NULL,
  token TEXT NOT NULL,
  addresses_v4 TEXT NOT NULL,
  addresses_v6 TEXT NOT NULL,
  peer_public_key TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  rtt_ms INTEGER,
  success_count INTEGER DEFAULT 0,
  fail_count INTEGER DEFAULT 0,
  last_seen DATETIME,
  last_checked DATETIME,
  UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identity_id TEXT NOT NULL,
  endpoint_id INTEGER NOT NULL,
  config_text TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(identity_id) REFERENCES identities(id),
  FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_alive ON endpoints(success_count, fail_count, last_seen);
CREATE INDEX IF NOT EXISTS idx_endpoints_rtt ON endpoints(rtt_ms);
CREATE INDEX IF NOT EXISTS idx_identities_created ON identities(created_at);
