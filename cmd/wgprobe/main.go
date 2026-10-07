package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/example/warp-server/internal/db"
	"github.com/example/warp-server/internal/scanner"
)

func main() {
	dbPath := flag.String("db", "", "path to warp.db (default: $DB_PATH or warp.db)")
	timeout := flag.Duration("timeout", 3*time.Second, "read timeout per attempt")
	attempts := flag.Int("attempts", 1, "handshake attempts per target")
	privKey := flag.String("priv", "", "override private key (base64)")
	pubKey := flag.String("pub", "", "override public key (base64)")
	peerKey := flag.String("peer", "", "override peer public key (base64)")
	flag.Parse()

	var priv, pub, peer string
	if *privKey != "" || *pubKey != "" || *peerKey != "" {
		priv, pub, peer = *privKey, *pubKey, *peerKey
	} else {
		if *dbPath == "" {
			*dbPath = os.Getenv("DB_PATH")
		}
		if *dbPath == "" {
			*dbPath = "warp.db"
		}
		database, err := db.New(*dbPath)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
		defer database.Close()
		ids, err := database.GetIdentities()
		if err != nil || len(ids) == 0 {
			log.Fatal("no identities in db; run 'worker register' first")
		}
		id := ids[0]
		priv, pub, peer = id.PrivateKey, id.PublicKey, id.PeerPublicKey
	}

	prober, err := scanner.NewProber(priv, pub, peer)
	if err != nil {
		log.Fatalf("new prober: %v", err)
	}

	// Default target list: a spread of Cloudflare WARP endpoints.
	targets := [][2]interface{}{
		{"162.159.192.5", 2408},
		{"162.159.192.5", 500},
		{"162.159.192.1", 2408},
		{"162.159.193.5", 2408},
		{"162.159.195.5", 2408},
		{"188.114.96.1", 2408},
		{"188.114.97.2", 2408},
		{"188.114.99.1", 2408},
	}
	if flag.NArg() >= 1 {
		host := flag.Arg(0)
		targets = nil
		if flag.NArg() >= 2 {
			var ports []int
			for i := 1; i < flag.NArg(); i++ {
				var p int
				fmt.Sscanf(flag.Arg(i), "%d", &p)
				ports = append(ports, p)
			}
			for _, p := range ports {
				targets = append(targets, [2]interface{}{host, p})
			}
		} else {
			for _, p := range []int{2408, 500, 443} {
				targets = append(targets, [2]interface{}{host, p})
			}
		}
	}

	for _, t := range targets {
		host := t[0].(string)
		port := t[1].(int)
		for a := 0; a < *attempts; a++ {
			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			rtt, raw, rt, senderIdx, err := prober.ProbeRaw(ctx, host, port)
			cancel()

			got := "NO-REPLY"
			if err == nil {
				pkt := "?"
				if len(raw) >= 4 {
					pkt = fmt.Sprintf("%d", int(reduceU32(raw)))
				}
				verified := "n/a"
				if len(raw) >= 4 {
					if prober.VerifyReply(raw, senderIdx) {
						verified = "STRICT-OK"
					} else {
						verified = "STRICT-FAIL"
					}
				}
				got = fmt.Sprintf("REPLY bytes=%d type=%v pktu32=%s rtt=%dms %s", len(raw), rt, pkt, rtt, verified)
			} else {
				got = fmt.Sprintf("ERR %v", err)
			}
			fmt.Printf("%-16s:%-6d [try %d] %s\n", host, port, a+1, got)
		}
	}
}

func reduceU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
