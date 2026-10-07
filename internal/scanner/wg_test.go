package scanner

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"encoding/base64"
	"encoding/binary"
)

type responder struct {
	staticPriv []byte
	staticPub  []byte
}

func newResponder() *responder {
	priv := make([]byte, 32)
	rand.Read(priv)
	return &responder{staticPriv: priv, staticPub: scalarBase(priv)}
}

func aeadOpen(key, ad, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Open(nil, nonce, ct, ad)
}

// consumeInitiation processes a handshake-initiation and, on success, returns
// a handshake-response message plus the hash/chaining key state so the helper
// can build the response.
type respState struct {
	hash, ck    []byte
	receiverIdx uint32
}

func (r *responder) consumeInitiation(msg []byte) (*respState, error) {
	if len(msg) != wgInitiationLen {
		return nil, errLen
	}
	initiatorIdx := binary.LittleEndian.Uint32(msg[wgInitSender : wgInitSender+4])
	ephemeral := msg[wgInitEphemeral:wgInitStatic]
	encStatic := msg[wgInitStatic:wgInitTimestamp]
	encTimestamp := msg[wgInitTimestamp:wgInitMac1]
	msgMac1 := msg[wgInitMac1:wgInitMac2]

	ck := wgHash([]byte(wgConstruction))
	hash := wgHash(wgHash(ck, []byte(wgIdentifier)), r.staticPub)
	hash = wgHash(hash, ephemeral)

	temp := hmacBlake2s(ck, ephemeral)
	ck = hmacBlake2s(temp, []byte{0x01})
	temp = hmacBlake2s(ck, dh(r.staticPriv, ephemeral))
	ck = hmacBlake2s(temp, []byte{0x01})
	key := hmacBlake2s(temp, ck, []byte{0x02})

	staticPub, err := aeadOpen(key, hash, encStatic)
	if err != nil {
		return nil, err
	}
	hash = wgHash(hash, encStatic)
	initiatorStatic := staticPub

	temp = hmacBlake2s(ck, dh(r.staticPriv, initiatorStatic))
	ck = hmacBlake2s(temp, []byte{0x01})
	key = hmacBlake2s(temp, ck, []byte{0x02})
	if _, err := aeadOpen(key, hash, encTimestamp); err != nil {
		return nil, err
	}
	hash = wgHash(hash, encTimestamp)

	mac1Key := wgHash([]byte(wgLabelMac1), r.staticPub)
	if !equal(mac16(mac1Key, msg[0:wgInitMac1]), msgMac1) {
		return nil, errMac
	}

	return &respState{hash: hash, ck: ck, receiverIdx: initiatorIdx}, nil
}

func (r *responder) buildResponse(st *respState, initiatorStatic, initiatorEphemeral []byte) []byte {
	ephemeralPriv := make([]byte, 32)
	rand.Read(ephemeralPriv)

	out := make([]byte, wgResponseLen)
	binary.LittleEndian.PutUint32(out[0:4], wgMsgHandshakeResponse)
	binary.LittleEndian.PutUint32(out[wgRespSender:wgRespSender+4], uint32(0xdeadbeef)) // responder sender index
	binary.LittleEndian.PutUint32(out[wgRespReceiver:wgRespReceiver+4], st.receiverIdx)
	ephemeralPub := scalarBase(ephemeralPriv)
	copy(out[wgRespEphemeral:wgRespMac1], ephemeralPub)

	hash := wgHash(st.hash, ephemeralPub)
	ck := st.ck

	temp := hmacBlake2s(ck, ephemeralPub)
	ck = hmacBlake2s(temp, []byte{0x01})
	temp = hmacBlake2s(ck, dh(ephemeralPriv, initiatorEphemeral))
	ck = hmacBlake2s(temp, []byte{0x01})
	temp = hmacBlake2s(ck, dh(ephemeralPriv, initiatorStatic))
	ck = hmacBlake2s(temp, []byte{0x01})
	temp = hmacBlake2s(ck, make([]byte, 32)) // psk = zero
	ck = hmacBlake2s(temp, []byte{0x01})
	temp2 := hmacBlake2s(temp, ck, []byte{0x02})
	key := hmacBlake2s(temp, temp2, []byte{0x03})
	hash = wgHash(hash, temp2)

	encNothing := aeadSeal(key, hash, nil)
	copy(out[wgRespEphemeral+32:wgRespMac1], encNothing)
	hash = wgHash(hash, encNothing)

	mac1Key := wgHash([]byte(wgLabelMac1), initiatorStatic)
	copy(out[wgRespMac1:wgRespMac1+16], mac16(mac1Key, out[0:wgRespMac1]))
	return out
}

var (
	errLen = errT("bad length")
	errMac = errT("bad mac1")
)

type errT string

func (e errT) Error() string { return string(e) }

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWireGuardHandshakeRoundTrip(t *testing.T) {
	r := newResponder()

	// Simulate a registered identity: our initiator static keypair + the
	// responder's public key.
	initStaticPriv := make([]byte, 32)
	rand.Read(initStaticPriv)
	initStaticPub := scalarBase(initStaticPriv)

	prober := &Prober{
		staticPriv: initStaticPriv,
		staticPub:  initStaticPub,
		peerPub:    r.staticPub,
	}

	initMsg, senderIndex := prober.buildInitiation()
	if len(initMsg) != wgInitiationLen {
		t.Fatalf("initiation length = %d, want %d", len(initMsg), wgInitiationLen)
	}

	st, err := r.consumeInitiation(initMsg)
	if err != nil {
		t.Fatalf("responder rejected valid initiation: %v", err)
	}

	// initiator ephemeral pub is embedded at [wgInitEphemeral:wgInitStatic]
	initiatorEphemeral := initMsg[wgInitEphemeral:wgInitStatic]
	respMsg := r.buildResponse(st, initStaticPub, initiatorEphemeral)
	if len(respMsg) != wgResponseLen {
		t.Fatalf("response length = %d, want %d", len(respMsg), wgResponseLen)
	}

	if !prober.verifyResponse(respMsg, senderIndex) {
		t.Fatal("prober failed to verify genuine handshake response")
	}

	// Corrupt the response's MAC1: must no longer verify.
	bad := append([]byte(nil), respMsg...)
	bad[wgRespMac1] ^= 0xff
	if prober.verifyResponse(bad, senderIndex) {
		t.Fatal("prober accepted corrupted response")
	}
}

func TestVerifyResponseRejectsGarbage(t *testing.T) {
	prober := &Prober{staticPub: make([]byte, 32)}
	if prober.verifyResponse([]byte{1, 2, 3}, 0) {
		t.Fatal("short message accepted")
	}
	if prober.verifyResponse(make([]byte, wgResponseLen), 0) {
		t.Fatal("zeroed response accepted")
	}
}

func TestBase64Keys(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	b64 := base64.StdEncoding.EncodeToString(key)
	got, err := decodeKey(b64)
	if err != nil || !equal(got, key) {
		t.Fatalf("decodeKey failed: %v", err)
	}
	if _, err := decodeKey("abc"); err == nil {
		t.Fatal("decodeKey accepted invalid base64")
	}
}
