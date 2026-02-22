package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"nestren-protocol/internal/protocol"
	"nestren-protocol/internal/security"
	"nestren-protocol/internal/traffic"
)

func main() {
	pub, priv, _ := security.NewSigningKeypair()
	token := security.IdentityToken{
		Subject:   "workload://edge-gw-01",
		Audience:  "nestren-control-plane",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Nonce:     "nonce-1",
	}
	token.Sign(priv)
	if err := security.ValidateIdentityToken(token, pub, "nestren-control-plane", time.Now()); err != nil {
		panic(err)
	}

	hello, clientSK, _ := protocol.BuildClientHello(token.Serialize())
	pqShared := make([]byte, 32)
	_, _ = rand.Read(pqShared)
	masterSecret, _ := protocol.DeriveHandshakeSecret(clientSK, hello.X25519Pub, pqShared)

	r := security.RekeyState{CurrentEpoch: 1, CurrentKey: security.DeriveTrafficKey(masterSecret, 1, "traffic")}
	r.Rotate(masterSecret)

	delay := traffic.JitterDelay(20*time.Millisecond, 10*time.Millisecond)
	fmt.Printf("NESTREN node started. next-epoch=%d jitter=%s dummy=%v\n", r.NextEpoch, delay, traffic.ShouldSendDummy(20))
}
