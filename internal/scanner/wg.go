package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"net"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	wgConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	wgLabelMac1    = "mac1----"

	wgMsgHandshakeInitiation = 1
	wgMsgHandshakeResponse   = 2
	wgMsgCookieReply         = 3

	wgInitiationLen  = 148
	wgResponseLen    = 92
	wgCookieReplyLen = 64
	wgTimestampLen   = 12

	// Canonical WireGuard wire layout (message_handshake_* per the reference):
	// there are NO reserved bytes after the 4-byte type; the initiator sender
	// index immediately follows the type at offset 4.
	wgInitSender   = 4
	wgInitEphemeral = 8
	wgInitStatic   = 40
	wgInitTimestamp = 88
	wgInitMac1     = 116
	wgInitMac2     = 132

	wgRespSender   = 4
	wgRespReceiver = 8
	wgRespEphemeral = 12
	wgRespMac1     = 60

	wgCookieReceiver = 4
)

// Prober builds and verifies WireGuard handshake messages against a single
// responder (the WARP peer) using the registered identity's keys.
type Prober struct {
	staticPriv []byte
	staticPub  []byte
	peerPub    []byte
}

// NewProber creates a Prober from base64-encoded keys.
func NewProber(privateKeyB64, publicKeyB64, peerPublicKeyB64 string) (*Prober, error) {
	priv, err := decodeKey(privateKeyB64)
	if err != nil {
		return nil, err
	}
	pub, err := decodeKey(publicKeyB64)
	if err != nil {
		return nil, err
	}
	peer, err := decodeKey(peerPublicKeyB64)
	if err != nil {
		return nil, err
	}
	return &Prober{staticPriv: priv, staticPub: pub, peerPub: peer}, nil
}

func decodeKey(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}
	return key, nil
}

// buildInitiation constructs a WireGuard handshake-initiation message (148
// bytes) for the WARP peer and returns the sender index used.
func (p *Prober) buildInitiation() ([]byte, uint32) {
	msg := make([]byte, wgInitiationLen)
	binary.LittleEndian.PutUint32(msg[0:4], wgMsgHandshakeInitiation)

	senderIndex := randomUint32()
	binary.LittleEndian.PutUint32(msg[wgInitSender:wgInitSender+4], senderIndex)

	ephemeralPriv := make([]byte, 32)
	rand.Read(ephemeralPriv)
	ephemeralPub := scalarBase(ephemeralPriv)
	copy(msg[wgInitEphemeral:wgInitStatic], ephemeralPub)

	ck := wgHash([]byte(wgConstruction))
	hash := wgHash(wgHash(ck, []byte(wgIdentifier)), p.peerPub)

	hash = wgHash(hash, ephemeralPub)
	temp := hmacBlake2s(ck, ephemeralPub)
	ck = hmacBlake2s(temp, []byte{0x01})
	temp = hmacBlake2s(ck, dh(ephemeralPriv, p.peerPub))
	ck = hmacBlake2s(temp, []byte{0x01})
	key := hmacBlake2s(temp, ck, []byte{0x02})

	encStatic := aeadSeal(key, hash, p.staticPub)
	copy(msg[wgInitStatic:wgInitTimestamp], encStatic)
	hash = wgHash(hash, encStatic)

	temp = hmacBlake2s(ck, dh(p.staticPriv, p.peerPub))
	ck = hmacBlake2s(temp, []byte{0x01})
	key = hmacBlake2s(temp, ck, []byte{0x02})

	encTimestamp := aeadSeal(key, hash, tai64now())
	copy(msg[wgInitTimestamp:wgInitMac1], encTimestamp)
	hash = wgHash(hash, encTimestamp)

	// MAC1 covers everything before wgInitMac1 (exactly 116 bytes).
	mac1Key := wgHash([]byte(wgLabelMac1), p.peerPub)
	mac1 := mac16(mac1Key, msg[0:wgInitMac1])
	copy(msg[wgInitMac1:wgInitMac2], mac1)

	return msg, senderIndex
}

// ResponseType describes the kind of WireGuard packet received.
type ResponseType int

const (
	ResponseNone ResponseType = iota
	ResponseHandshake
	ResponseCookie
	ResponseOther
)

// VerifyReply reports whether data is a genuine handshake response or cookie
// reply addressed to the given sender index (strict verification).
func (p *Prober) VerifyReply(data []byte, senderIndex uint32) bool {
	return p.verifyResponse(data, senderIndex)
}

// ProbeRaw performs a single handshake to host:port over UDP and returns the
// round-trip time, the raw reply bytes, and what kind of reply it was. It is
// intended for diagnostics and is more lenient than ProbeEndpoint.
func (p *Prober) ProbeRaw(ctx context.Context, host string, port int) (int, []byte, ResponseType, uint32, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return 0, nil, ResponseNone, 0, errors.New("invalid host")
	}
	msg, senderIndex := p.buildInitiation()

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return 0, nil, ResponseNone, 0, err
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)

	start := time.Now()
	if _, err = conn.Write(msg); err != nil {
		return 0, nil, ResponseNone, 0, err
	}

	rx := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(rx)
		if err != nil {
			return int(time.Since(start).Milliseconds()), nil, ResponseNone, senderIndex, err
		}
		rt := classifyResponse(rx[:n], senderIndex)
		if rt != ResponseOther {
			return int(time.Since(start).Milliseconds()), append([]byte(nil), rx[:n]...), rt, senderIndex, nil
		}
	}
}

// classifyResponse returns the kind of reply and whether our verifyResponse
// accepts it.
func classifyResponse(data []byte, senderIndex uint32) ResponseType {
	if len(data) < 4 {
		return ResponseOther
	}
	msgType := binary.LittleEndian.Uint32(data[0:4])
	switch msgType {
	case wgMsgHandshakeResponse:
		return ResponseHandshake
	case wgMsgCookieReply:
		return ResponseCookie
	default:
		return ResponseOther
	}
}

// verifyResponse validates a reply as a genuine WireGuard handshake response
// (or cookie reply) addressed to the given sender index.
func (p *Prober) verifyResponse(data []byte, senderIndex uint32) bool {
	if len(data) < 4 {
		return false
	}
	msgType := binary.LittleEndian.Uint32(data[0:4])
	switch msgType {
	case wgMsgCookieReply:
		if len(data) < wgCookieReplyLen {
			return false
		}
		return binary.LittleEndian.Uint32(data[wgCookieReceiver:wgCookieReceiver+4]) == senderIndex
	case wgMsgHandshakeResponse:
		if len(data) < wgResponseLen {
			return false
		}
		if binary.LittleEndian.Uint32(data[wgRespReceiver:wgRespReceiver+4]) != senderIndex {
			return false
		}
		mac1Key := wgHash([]byte(wgLabelMac1), p.staticPub)
		want := mac16(mac1Key, data[0:wgRespMac1])
		return subtle.ConstantTimeCompare(want, data[wgRespMac1:wgRespMac1+16]) == 1
	default:
		return false
	}
}

func randomUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

// scalarBase returns X25519(priv, basepoint) in a fresh buffer.
func scalarBase(priv []byte) []byte {
	return scalarMult(priv, curve25519.Basepoint)
}

// scalarMult returns X25519(priv, pub) in a fresh buffer. The result must be
// copied because curve25519 returns slices backed by a reused internal buffer.
func scalarMult(priv, pub []byte) []byte {
	out, err := curve25519.X25519(priv, pub)
	if err != nil {
		return make([]byte, 32)
	}
	return append([]byte(nil), out...)
}

func dh(priv, pub []byte) []byte {
	return scalarMult(priv, pub)
}

func aeadSeal(key, ad, plaintext []byte) []byte {
	aead, _ := chacha20poly1305.New(key)
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, plaintext, ad)
}

func tai64now() []byte {
	now := time.Now()
	b := make([]byte, wgTimestampLen)
	sec := uint64(now.Unix()) + 0x400000000000000a
	binary.BigEndian.PutUint64(b[0:8], sec)
	binary.BigEndian.PutUint32(b[8:12], uint32(now.Nanosecond()))
	return b
}

func wgHash(data ...[]byte) []byte {
	h := blake2s.Sum256(concat(data...))
	return h[:]
}

func hmacBlake2s(key []byte, data ...[]byte) []byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum(nil)
}

func mac16(key, data []byte) []byte {
	m, _ := blake2s.New128(key)
	m.Write(data)
	return m.Sum(nil)
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
