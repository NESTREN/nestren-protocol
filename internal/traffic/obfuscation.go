package traffic

import (
	"crypto/rand"
	"math/big"
	"time"
)

// JitterDelay returns randomized delay to blur traffic patterns.
func JitterDelay(base time.Duration, spread time.Duration) time.Duration {
	if spread <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(spread)*2+1))
	if err != nil {
		return base
	}
	return base - spread + time.Duration(n.Int64())
}

// ShouldSendDummy emits low-rate cover traffic.
func ShouldSendDummy(permille int) bool {
	if permille <= 0 {
		return false
	}
	if permille >= 1000 {
		return true
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return false
	}
	return int(n.Int64()) < permille
}
