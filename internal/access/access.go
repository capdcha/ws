package access

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Trusted networks are the sources that count as "local":
//   - loopback (127.0.0.0/8, ::1)
//   - the container's own interface subnets (the docker compose network),
//     which is where the UI container and docker-proxy (host connections to
//     published ports are re-dialed from the bridge gateway) come from
//   - extra CIDRs from the TRUSTED_CIDRS environment variable
//
// Clients from any other address are treated as external.
var (
	once    sync.Once
	trusted []*net.IPNet
)

func initNetworks() {
	if _, n, err := net.ParseCIDR("127.0.0.0/8"); err == nil {
		trusted = append(trusted, n)
	}
	if _, n, err := net.ParseCIDR("::1/128"); err == nil {
		trusted = append(trusted, n)
	}

	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				if ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLinkLocalMulticast() {
					continue
				}
				trusted = append(trusted, &net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask})
			}
		}
	}

	for _, c := range strings.Split(os.Getenv("TRUSTED_CIDRS"), ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			trusted = append(trusted, n)
		}
	}
}

func TrustedNetworks() []*net.IPNet {
	once.Do(initNetworks)
	return trusted
}

func IsTrusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range TrustedNetworks() {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the peer address of the request. X-Forwarded-For is
// deliberately ignored: it is client-controlled and trivially spoofable.
func ClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}
