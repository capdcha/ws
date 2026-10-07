package scanner

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

type Endpoint struct {
	ID   int64
	Host string
	Port int
	RTT  int
}

type scanResult struct {
	addr *net.UDPAddr
	rtt  int
}

// ScanEndpoints probes WARP-style prefixes over UDP by sending a WireGuard
// handshake-initiation datagram to each candidate and recording every endpoint
// that replies with a handshake response or cookie reply. TCP is never used:
// WireGuard/WARP endpoints only listen on UDP.
func ScanEndpoints(ctx context.Context, prefixes []string, ports []int, maxResults int, keys *IdentityKeys) ([]Endpoint, error) {
	if len(prefixes) == 0 || len(ports) == 0 {
		return []Endpoint{}, nil
	}

	if d, ok := ctx.Deadline(); !ok || time.Until(d) > 60*time.Second {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}

	prober, err := NewProber(keys.PrivateKey, keys.PublicKey, keys.PeerPublicKey)
	if err != nil {
		return nil, err
	}
	initMsg, senderIndex := prober.buildInitiation()

	var addrs []*net.UDPAddr
	for _, prefix := range prefixes {
		ip, ipnet, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			for _, port := range ports {
				addrs = append(addrs, &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port})
			}
		}
	}

	const workers = 256
	const readWindow = 4 * time.Second

	resultCh := make(chan scanResult, 4096)

	var mu sync.Mutex
	var results []scanResult

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerIdx int) {
			defer wg.Done()
			scanWorker(ctx, workerIdx, workers, addrs, initMsg, senderIndex, prober, readWindow, resultCh)
		}(i)
	}

	// Drain results concurrently with the workers so a large number of
	// findings never blocks the senders (the previous design collected only
	// after wg.Wait(), which deadlocked once the channel buffer filled).
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for r := range resultCh {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}
	}()

	wg.Wait()
	close(resultCh)
	<-drainDone

	seen := make(map[string]bool)
	out := make([]Endpoint, 0, len(results))
	for _, r := range results {
		key := r.addr.IP.String() + ":" + strconv.Itoa(r.addr.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Endpoint{Host: r.addr.IP.String(), Port: r.addr.Port, RTT: r.rtt})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].RTT < out[j].RTT
	})
	if len(out) > maxResults {
		out = out[:maxResults]
	}
	return out, nil
}

func scanWorker(ctx context.Context, workerIdx, workers int, addrs []*net.UDPAddr, initMsg []byte, senderIndex uint32, prober *Prober, readWindow time.Duration, resultCh chan<- scanResult) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}
	defer conn.Close()

	type pending struct {
		ipn   int64
		found bool
	}
	sent := make(map[string]pending, len(addrs)/workers)

	// Send a handshake initiation to every assigned address from this socket.
	for i := workerIdx; i < len(addrs); i += workers {
		if ctx.Err() != nil {
			return
		}
		addr := addrs[i]
		if _, err := conn.WriteToUDP(initMsg, addr); err != nil {
			continue
		}
		key := addr.IP.String() + ":" + strconv.Itoa(addr.Port)
		sent[key] = pending{ipn: time.Now().UnixNano()}
	}

	// Collect replies for a short window.
	conn.SetReadDeadline(time.Now().Add(readWindow))
	rx := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDP(rx)
		if err != nil {
			return
		}
		if !prober.verifyResponse(rx[:n], senderIndex) {
			continue
		}
		key := from.IP.String() + ":" + strconv.Itoa(from.Port)
		p, ok := sent[key]
		if !ok || p.found {
			continue
		}
		p.found = true
		sent[key] = p
		resultCh <- scanResult{addr: &net.UDPAddr{IP: from.IP, Port: from.Port}, rtt: int(time.Since(time.Unix(0, p.ipn)).Milliseconds())}
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
