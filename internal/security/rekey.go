package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// RekeyState supports seamless key rotation using overlapped epochs.
type RekeyState struct {
	CurrentEpoch uint32
	CurrentKey   []byte
	NextEpoch    uint32
	NextKey      []byte
}

func DeriveTrafficKey(masterSecret []byte, epoch uint32, label string) []byte {
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte(label))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, epoch)
	mac.Write(buf)
	return mac.Sum(nil)[:32]
}

func (r *RekeyState) Rotate(masterSecret []byte) {
	r.NextEpoch = r.CurrentEpoch + 1
	r.NextKey = DeriveTrafficKey(masterSecret, r.NextEpoch, "traffic")
}

func (r *RekeyState) PromoteNext() {
	if r.NextEpoch == 0 || len(r.NextKey) == 0 {
		return
	}
	r.CurrentEpoch = r.NextEpoch
	r.CurrentKey = r.NextKey
	r.NextEpoch = 0
	r.NextKey = nil
}
