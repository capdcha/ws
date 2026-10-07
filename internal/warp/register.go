package warp

import (
  "bytes"
  "context"
  "encoding/json"
  "fmt"
  "net/http"
  "time"
  "github.com/example/warp-server/internal/crypto"
  "encoding/base64"
)

const RegURL = "https://api.cloudflareclient.com/v0a4471/reg"

type Identity struct {
  ID             string
  PrivateKey     string
  PublicKey      string
  ClientID       string
  Token          string
  AddressesV4    []string
  AddressesV6    []string
  PeerPublicKey  string
}

func RegisterIdentity(ctx context.Context) (*Identity, error) {
  privKey, pubKey, err := crypto.GenerateX25519()
  if err != nil {
    return nil, err
  }
  
  body := map[string]interface{}{
    "key": base64.StdEncoding.EncodeToString(pubKey),
    "install_id": "",
    "fcm_token": "",
    "tos": "2023-01-01T00:00:00.000Z",
    "type": "Android",
    "locale": "en_US",
  }
  
  bodyJSON, _ := json.Marshal(body)
  req, _ := http.NewRequestWithContext(ctx, "POST", RegURL, bytes.NewReader(bodyJSON))
  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("CF-Client-Version", "a-6.35-4471")
  req.Header.Set("User-Agent", "okhttp/3.12.1")
  
  client := &http.Client{Timeout: 15 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()
  
  if resp.StatusCode != 200 {
    return nil, fmt.Errorf("registration failed: %d", resp.StatusCode)
  }
  
  var result struct {
    ID     string `json:"id"`
    Token  string `json:"token"`
    Config struct {
      ClientID  string `json:"client_id"`
      Peers     []struct {
        Endpoint  struct {
          V4   string `json:"v4"`
          V6   string `json:"v6"`
          Host string `json:"host"`
        } `json:"endpoint"`
        PublicKey string `json:"public_key"`
      } `json:"peers"`
      Interface struct {
        Addresses struct {
          V4 string `json:"v4"`
          V6 string `json:"v6"`
        } `json:"addresses"`
      } `json:"interface"`
    } `json:"config"`
  }
  
  if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
    return nil, err
  }
  
  return &Identity{
    ID:            result.ID,
    PrivateKey:    base64.StdEncoding.EncodeToString(privKey),
    PublicKey:     base64.StdEncoding.EncodeToString(pubKey),
    ClientID:      result.Config.ClientID,
    Token:         result.Token,
    AddressesV4:   []string{result.Config.Interface.Addresses.V4},
    AddressesV6:   []string{result.Config.Interface.Addresses.V6},
    PeerPublicKey: result.Config.Peers[0].PublicKey,
  }, nil
}
