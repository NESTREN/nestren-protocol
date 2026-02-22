package protocol

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	Version            = uint16(1)
	CipherSuiteHybrid1 = uint16(0xA101) // X25519 + PQ-KEM placeholder, AES-256-GCM, SHA-384
	ReplayWindow       = 30 * time.Second
)

// ClientHello bootstraps a hybrid key exchange and downgrade resistance.
type ClientHello struct {
	Version         uint16
	SupportedSuites []uint16
	TimestampUnix   int64
	ClientNonce     [16]byte
	X25519Pub       []byte
	PQKemPublic     []byte
	IdentityToken   string
}

// ServerHello binds server response to transcript and client hello.
type ServerHello struct {
	Version       uint16
	Suite         uint16
	TimestampUnix int64
	ServerNonce   [16]byte
	X25519Pub     []byte
	PQCiphertext  []byte
	FinishedMAC   []byte
}

func BuildClientHello(identityToken string) (ClientHello, *ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	sk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return ClientHello{}, nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return ClientHello{}, nil, err
	}

	// PQKemPublic is a placeholder for ML-KEM public key bytes.
	pq := make([]byte, 1184)
	if _, err = rand.Read(pq); err != nil {
		return ClientHello{}, nil, err
	}

	return ClientHello{
		Version:         Version,
		SupportedSuites: []uint16{CipherSuiteHybrid1},
		TimestampUnix:   time.Now().Unix(),
		ClientNonce:     nonce,
		X25519Pub:       sk.PublicKey().Bytes(),
		PQKemPublic:     pq,
		IdentityToken:   identityToken,
	}, sk, nil
}

func DeriveHandshakeSecret(clientSK *ecdh.PrivateKey, serverPub []byte, pqSharedSecret []byte) ([]byte, error) {
	spk, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, err
	}
	xSecret, err := clientSK.ECDH(spk)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(xSecret)
	h.Write(pqSharedSecret)
	return h.Sum(nil), nil
}

func ValidateServerHello(ch ClientHello, sh ServerHello, handshakeSecret []byte) error {
	if sh.Version != Version {
		return errors.New("downgrade detected: protocol version mismatch")
	}
	if sh.Suite != CipherSuiteHybrid1 {
		return errors.New("downgrade detected: unsupported suite")
	}
	if time.Since(time.Unix(sh.TimestampUnix, 0)) > ReplayWindow {
		return errors.New("possible replay: stale server hello")
	}
	transcript := transcriptHash(ch, sh)
	mac := hmac.New(sha256.New, handshakeSecret)
	mac.Write(transcript)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, sh.FinishedMAC) {
		return errors.New("MITM detected: transcript MAC mismatch")
	}
	return nil
}

func transcriptHash(ch ClientHello, sh ServerHello) []byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, ch.Version)
	_ = binary.Write(h, binary.BigEndian, ch.TimestampUnix)
	h.Write(ch.ClientNonce[:])
	h.Write(ch.X25519Pub)
	h.Write(ch.PQKemPublic)
	_ = binary.Write(h, binary.BigEndian, sh.Version)
	_ = binary.Write(h, binary.BigEndian, sh.TimestampUnix)
	h.Write(sh.ServerNonce[:])
	h.Write(sh.X25519Pub)
	h.Write(sh.PQCiphertext)
	return h.Sum(nil)
}
