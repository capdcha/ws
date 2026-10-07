package db

import (
  "encoding/json"
  "github.com/example/warp-server/internal/warp"
)

func (db *DB) InsertIdentity(id *warp.Identity) error {
  v4JSON, _ := json.Marshal(id.AddressesV4)
  v6JSON, _ := json.Marshal(id.AddressesV6)
  
  _, err := db.conn.Exec(`
    INSERT INTO identities 
    (id, private_key, public_key, client_id, token, addresses_v4, addresses_v6, peer_public_key)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    id.ID, id.PrivateKey, id.PublicKey, id.ClientID, id.Token,
    string(v4JSON), string(v6JSON), id.PeerPublicKey,
  )
  return err
}

func (db *DB) GetIdentities() ([]*warp.Identity, error) {
  rows, err := db.conn.Query("SELECT id, private_key, public_key, client_id, token, addresses_v4, addresses_v6, peer_public_key FROM identities")
  if err != nil {
    return nil, err
  }
  defer rows.Close()
  
  var result []*warp.Identity
  for rows.Next() {
    var id warp.Identity
    var v4JSON, v6JSON string
    rows.Scan(&id.ID, &id.PrivateKey, &id.PublicKey, &id.ClientID, &id.Token, &v4JSON, &v6JSON, &id.PeerPublicKey)
    json.Unmarshal([]byte(v4JSON), &id.AddressesV4)
    json.Unmarshal([]byte(v6JSON), &id.AddressesV6)
    result = append(result, &id)
  }
  return result, nil
}
