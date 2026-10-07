package crypto

import (
  "crypto/rand"
  "golang.org/x/crypto/curve25519"
)

func GenerateX25519() (privateKey, publicKey []byte, err error) {
  privateKey = make([]byte, 32)
  if _, err := rand.Read(privateKey); err != nil {
    return nil, nil, err
  }
  
  publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
  if err != nil {
    return nil, nil, err
  }
  
  return privateKey, publicKey, nil
}
