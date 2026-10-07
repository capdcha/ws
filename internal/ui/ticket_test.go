package ui

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"
)

var testIP = net.ParseIP("198.51.100.4")

func TestTicketRoundTrip(t *testing.T) {
	ts := newTicketStore()
	token, err := ts.issue(testIP)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := ts.verify(token, testIP); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Reuse is allowed within the limit.
	for i := 1; i < ticketMaxUses; i++ {
		if err := ts.verify(token, testIP); err != nil {
			t.Fatalf("reuse %d: %v", i, err)
		}
	}
	if err := ts.verify(token, testIP); err != errTicketExhausted {
		t.Fatalf("after limit err = %v, want %v", err, errTicketExhausted)
	}
}

func TestTicketRejects(t *testing.T) {
	ts := newTicketStore()
	token, err := ts.issue(testIP)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	cases := []struct {
		name string
		ip   net.IP
		tok  string
		want error
	}{
		{"wrong ip", net.ParseIP("203.0.113.9"), token, errTicketWrongIP},
		{"empty", testIP, "", errTicketMissing},
		{"garbage", testIP, "deadbeef", errTicketMalformed},
		{"two parts, bad sig", testIP, "aa.bb", errTicketSignature},
	}
	for _, c := range cases {
		if err := ts.verify(c.tok, c.ip); err != c.want {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestTicketExpiry(t *testing.T) {
	ts := newTicketStore()
	body, _ := json.Marshal(ticketPayload{
		V:     1,
		Ts:    time.Now().Add(-time.Hour).Unix(),
		IP:    testIP.String(),
		Nonce: "abc",
	})
	token := signTicket(ts.secret, body)
	if err := ts.verify(token, testIP); err != errTicketExpired {
		t.Fatalf("old ticket err = %v, want %v", err, errTicketExpired)
	}
}

func TestTicketTamper(t *testing.T) {
	ts := newTicketStore()
	token, _ := ts.issue(testIP)

	// Flip a byte in the signature part.
	dot := 0
	for i, r := range token {
		if r == '.' {
			dot = i
			break
		}
	}
	sig, _ := base64.RawURLEncoding.DecodeString(token[dot+1:])
	sig[0] ^= 0xff
	tampered := token[:dot+1] + base64.RawURLEncoding.EncodeToString(sig)
	if err := ts.verify(tampered, testIP); err != errTicketSignature {
		t.Fatalf("tampered err = %v, want %v", err, errTicketSignature)
	}

	// Re-signed payload with a manipulated timestamp must not verify either.
	body, _ := json.Marshal(ticketPayload{
		V:     1,
		Ts:    time.Now().Unix(),
		IP:    testIP.String(),
		Nonce: "abc",
	})
	other := newTicketStore()
	if err := ts.verify(signTicket(other.secret, body), testIP); err != errTicketSignature {
		t.Fatalf("foreign secret err = %v, want %v", err, errTicketSignature)
	}
}
