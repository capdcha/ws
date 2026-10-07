package scanner

import (
	"context"
	"net"
	"time"
)

type IdentityKeys struct {
	PrivateKey    string
	PublicKey     string
	PeerPublicKey string
}

// ProbeEndpoint performs a real WireGuard handshake against the endpoint over
// UDP and returns the round-trip time. It succeeds only if the endpoint
// authenticates as a genuine WireGuard peer.
func ProbeEndpoint(ctx context.Context, endpoint Endpoint, keys *IdentityKeys) (int, error) {
	prober, err := NewProber(keys.PrivateKey, keys.PublicKey, keys.PeerPublicKey)
	if err != nil {
		return 0, err
	}

	ip := net.ParseIP(endpoint.Host)
	if ip == nil {
		return 0, &net.AddrError{Err: "invalid host", Addr: endpoint.Host}
	}

	start := time.Now()
	msg, senderIndex := prober.buildInitiation()

	raddr := &net.UDPAddr{IP: ip, Port: endpoint.Port}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)

	if _, err = conn.Write(msg); err != nil {
		return 0, err
	}

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}
		if prober.verifyResponse(buf[:n], senderIndex) {
			return int(time.Since(start).Milliseconds()), nil
		}
	}
}
