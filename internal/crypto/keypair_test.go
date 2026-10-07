package crypto

import "testing"

func TestGenerateX25519(t *testing.T) {
  priv, pub, err := GenerateX25519()
  if err != nil {
    t.Fatal(err)
  }
  if len(priv) != 32 {
    t.Errorf("private key length = %d, want 32", len(priv))
  }
  if len(pub) != 32 {
    t.Errorf("public key length = %d, want 32", len(pub))
  }
}
