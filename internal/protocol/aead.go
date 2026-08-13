package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

type Direction uint32

const (
	DirectionClientToServer Direction = 1
	DirectionServerToClient Direction = 2
)

// 규격에 맞는 키 생성 (32 byte 규격의 키 생성)
func deriveMasterKey(psk []byte) [sha256.Size]byte {
	return sha256.Sum256(psk)
}

func deriveHandshakeKey(masterKey [sha256.Size]byte, clientRandom HandshakeRandom) [sha256.Size]byte {
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(clientRandom[:])

	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))

	return key
}

func derivePeerKey(masterKey [sha256.Size]byte, peerID uint64, clientRandom HandshakeRandom, serverRandom HandshakeRandom) [sha256.Size]byte {
	var peerIDBytes [8]byte
	binary.BigEndian.PutUint64(peerIDBytes[:], peerID)

	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(peerIDBytes[:])
	mac.Write(clientRandom[:])
	mac.Write(serverRandom[:])

	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))

	return key
}

type Cipher struct {
	aead cipher.AEAD
}

type CipherSuite struct {
	masterKey [sha256.Size]byte
}

func NewCipherSuite(psk []byte) (*CipherSuite, error) {
	if len(psk) == 0 {
		return nil, errors.New("psk is empty")
	}

	return &CipherSuite{
		masterKey: deriveMasterKey(psk),
	}, nil
}

func (cs *CipherSuite) NewHandshakeCipher(clientRandom HandshakeRandom) (*Cipher, error) {
	key := deriveHandshakeKey(cs.masterKey, clientRandom)

	return newCipherFromKey(key[:])
}

func (cs *CipherSuite) NewPeerCipher(peerID uint64, clientRandom HandshakeRandom, serverRandom HandshakeRandom) (*Cipher, error) {
	key := derivePeerKey(cs.masterKey, peerID, clientRandom, serverRandom)

	return newCipherFromKey(key[:])
}

func newCipherFromKey(key []byte) (*Cipher, error) {
	// AES 기본 엔진 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	// GCM 모드(AEAD 기능) 결합
	// 이 단계를 거쳐야 비로소 AEAD 기능(본문 암호화 + 헤더 AAD 인증 + 위변조 방지 태그 생성)
	// 을 수행하는 최종 암호화 도구(aead)가 완성됩니다.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes-gcm: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

func buildNonce(direction Direction, sequence uint64) []byte {
	var nonce [12]byte

	binary.BigEndian.PutUint32(nonce[0:4], uint32(direction))
	binary.BigEndian.PutUint64(nonce[4:12], sequence)

	return nonce[:]
}

/*
aad
암호화하지는 않지만 변조 검증할 데이터
나중에 header를 넣을 예정
*/
func (c *Cipher) SealPayload(direction Direction, sequence uint64, aad []byte, payload []byte) ([]byte, error) {
	nonce := buildNonce(direction, sequence)

	// ciphertext = [encrypted payload][authentication tag]
	ciphertext := c.aead.Seal(nil, nonce, payload, aad) // 암호화된 payload + AEAD tag
	return ciphertext, nil
}

func (c *Cipher) OpenPayload(direction Direction, sequence uint64, aad []byte, ciphertext []byte) ([]byte, error) {
	nonce := buildNonce(direction, sequence)

	payload, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to open AEAD payload: %v: %w", err, ErrAuthenticationFailed) // 실제 에러도 담아야되지 않나? %v: %w
	}

	return payload, nil
}
