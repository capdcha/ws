package warp

import (
  "fmt"
  "github.com/example/warp-server/internal/scanner"
  "math/rand"
)

func GenerateAmneziaConfig(identity *Identity, endpoint *scanner.Endpoint) string {
  // Обфускация параметры из Nova seeds
  jc := 4
  jmin := 40
  jmax := 70
  h1 := rand.Intn(4294967295)
  h2 := rand.Intn(4294967295)
  h3 := rand.Intn(4294967295)
  h4 := rand.Intn(4294967295)
  
  return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s, %s
DNS = 1.1.1.1, 1.0.0.1
Jc = %d
Jmin = %d
Jmax = %d
H1 = %d
H2 = %d
H3 = %d
H4 = %d

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0, ::/0
`,
    identity.PrivateKey,
    identity.AddressesV4[0], identity.AddressesV6[0],
    jc, jmin, jmax, h1, h2, h3, h4,
    identity.PeerPublicKey,
    endpoint.Host, endpoint.Port,
  )
}
