package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IdentityToken models short-lived Zero-Trust workload credentials.
type IdentityToken struct {
	Subject   string
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Nonce     string
	Signature []byte
}

func NewSigningKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func (t IdentityToken) payload() string {
	return fmt.Sprintf("sub=%s;aud=%s;iat=%d;exp=%d;nonce=%s",
		t.Subject,
		t.Audience,
		t.IssuedAt.Unix(),
		t.ExpiresAt.Unix(),
		t.Nonce,
	)
}

func (t *IdentityToken) Sign(sk ed25519.PrivateKey) {
	h := sha256.Sum256([]byte(t.payload()))
	t.Signature = ed25519.Sign(sk, h[:])
}

func (t IdentityToken) Serialize() string {
	sig := base64.RawURLEncoding.EncodeToString(t.Signature)
	return t.payload() + ";sig=" + sig
}

func ParseIdentityToken(raw string) (IdentityToken, error) {
	parts := strings.Split(raw, ";")
	if len(parts) < 6 {
		return IdentityToken{}, errors.New("malformed identity token")
	}
	fields := map[string]string{}
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			fields[kv[0]] = kv[1]
		}
	}
	iat, err := time.ParseDuration(fields["iat"] + "s")
	if err != nil {
		return IdentityToken{}, err
	}
	exp, err := time.ParseDuration(fields["exp"] + "s")
	if err != nil {
		return IdentityToken{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(fields["sig"])
	if err != nil {
		return IdentityToken{}, err
	}
	return IdentityToken{
		Subject:   fields["sub"],
		Audience:  fields["aud"],
		IssuedAt:  time.Unix(int64(iat.Seconds()), 0),
		ExpiresAt: time.Unix(int64(exp.Seconds()), 0),
		Nonce:     fields["nonce"],
		Signature: sig,
	}, nil
}

func ValidateIdentityToken(token IdentityToken, trustRoot ed25519.PublicKey, expectedAudience string, now time.Time) error {
	if token.Audience != expectedAudience {
		return errors.New("invalid audience")
	}
	if token.IssuedAt.After(now.Add(5 * time.Second)) {
		return errors.New("token from future")
	}
	if now.After(token.ExpiresAt) {
		return errors.New("token expired")
	}
	h := sha256.Sum256([]byte(token.payload()))
	if !ed25519.Verify(trustRoot, h[:], token.Signature) {
		return errors.New("invalid token signature")
	}
	return nil
}
