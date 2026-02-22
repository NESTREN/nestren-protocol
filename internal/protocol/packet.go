package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// SecurePacket defines authenticated record framing.
type SecurePacket struct {
	Type      uint8
	Epoch     uint32
	Sequence  uint64
	Length    uint16
	Padding   []byte
	Ciphertext []byte
	Tag       []byte
}

func EncryptPacket(trafficKey []byte, aad []byte, payload []byte, packetType uint8, epoch uint32, seq uint64, padTo int) ([]byte, error) {
	block, err := aes.NewCipher(trafficKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	padLen := 0
	if padTo > len(payload) {
		padLen = padTo - len(payload)
	}
	plain := append(append([]byte{}, payload...), make([]byte, padLen)...)
	if padLen > 0 {
		_, _ = rand.Read(plain[len(payload):])
	}

	nonce := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint32(nonce[:4], epoch)
	binary.BigEndian.PutUint64(nonce[4:], seq)

	frameHeader := make([]byte, 1+4+8+2)
	frameHeader[0] = packetType
	binary.BigEndian.PutUint32(frameHeader[1:5], epoch)
	binary.BigEndian.PutUint64(frameHeader[5:13], seq)
	binary.BigEndian.PutUint16(frameHeader[13:15], uint16(len(plain)))
	aadFrame := append(frameHeader, aad...)
	sealed := aead.Seal(nil, nonce, plain, aadFrame)
	return append(frameHeader, sealed...), nil
}

func DecryptPacket(trafficKey []byte, aad []byte, frame []byte) ([]byte, error) {
	if len(frame) < 15 {
		return nil, errors.New("short frame")
	}
	block, err := aes.NewCipher(trafficKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	epoch := binary.BigEndian.Uint32(frame[1:5])
	seq := binary.BigEndian.Uint64(frame[5:13])
	declaredLen := binary.BigEndian.Uint16(frame[13:15])
	ciphertext := frame[15:]

	nonce := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint32(nonce[:4], epoch)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	aadFrame := append(frame[:15], aad...)
	plain, err := aead.Open(nil, nonce, ciphertext, aadFrame)
	if err != nil {
		return nil, err
	}
	if len(plain) < int(declaredLen) {
		return nil, errors.New("length mismatch")
	}
	return plain[:declaredLen], nil
}
