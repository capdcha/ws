package ui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// The configuration page must not be reachable by a plain (bookmarked or
// shared) link. Every ticket is issued per request, carries a timestamp and
// the client address, is signed with HMAC-SHA256 and can only be used a
// limited number of times within its TTL.
//
// HMAC-SHA256 is used instead of RSA (or any asymmetric scheme) because the
// very same service both issues and verifies tickets: there is no second
// party to distribute a public key to, and hmac.Equal gives a constant-time
// comparison for free. RSA would only add key management.
const (
	ticketTTL     = 5 * time.Minute
	ticketMaxUses = 10
)

var (
	errTicketMissing   = errors.New("ticket missing")
	errTicketMalformed = errors.New("ticket malformed")
	errTicketSignature = errors.New("ticket signature mismatch")
	errTicketExpired   = errors.New("ticket expired")
	errTicketWrongIP   = errors.New("ticket issued for another address")
	errTicketExhausted = errors.New("ticket already used up")
)

type ticketPayload struct {
	V     int    `json:"v"`
	Ts    int64  `json:"ts"`
	IP    string `json:"ip"`
	Nonce string `json:"nonce"`
}

type ticketUse struct {
	count  int
	issued time.Time
}

type ticketStore struct {
	secret []byte
	mu     sync.Mutex
	uses   map[string]*ticketUse
}

func newTicketStore() *ticketStore {
	var secret []byte
	if v := os.Getenv("UI_TICKET_SECRET"); v != "" {
		secret = []byte(v)
	} else {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic("ui: cannot generate ticket secret: " + err.Error())
		}
	}
	return &ticketStore{secret: secret, uses: make(map[string]*ticketUse)}
}

func (t *ticketStore) issue(ip net.IP) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	body, err := json.Marshal(ticketPayload{
		V:     1,
		Ts:    time.Now().Unix(),
		IP:    ip.String(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return "", err
	}
	return signTicket(t.secret, body), nil
}

func signTicket(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (t *ticketStore) verify(token string, ip net.IP) error {
	if token == "" {
		return errTicketMissing
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errTicketMalformed
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errTicketMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errTicketMalformed
	}
	mac := hmac.New(sha256.New, t.secret)
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return errTicketSignature
	}

	var p ticketPayload
	if err := json.Unmarshal(body, &p); err != nil || p.V != 1 || p.Nonce == "" {
		return errTicketMalformed
	}

	now := time.Now()
	issued := time.Unix(p.Ts, 0)
	if issued.After(now.Add(time.Minute)) {
		return errTicketExpired
	}
	if now.Sub(issued) > ticketTTL {
		return errTicketExpired
	}
	if p.IP != ip.String() {
		return errTicketWrongIP
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(now)
	u := t.uses[token]
	if u == nil {
		t.uses[token] = &ticketUse{count: 1, issued: issued}
		return nil
	}
	if u.count >= ticketMaxUses {
		return errTicketExhausted
	}
	u.count++
	return nil
}

// prune drops tickets that are already older than the TTL, so the map cannot
// grow without bound.
func (t *ticketStore) prune(now time.Time) {
	if len(t.uses) < 512 {
		return
	}
	for k, u := range t.uses {
		if now.Sub(u.issued) > ticketTTL {
			delete(t.uses, k)
		}
	}
}
