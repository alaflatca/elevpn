package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

type Direction uint32

const (
	DirectionClientToServer Direction = 1
	DirectionServerToClient Direction = 2
)

func deriveAEADKey(psk []byte) []byte {
	sum := sha256.Sum256(psk)
	return sum[:]
}

type Cipher struct {
	aead cipher.AEAD
}

func NewCipher(psk []byte) (*Cipher, error) {
	// 1단계: 규격에 맞는 키 생성 (32 byte 규격의 키 생성)
	key := deriveAEADKey(psk)

	// 2단계: AES 기본 엔진 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	// 3단계: GCM 모드(AEAD 기능) 결합
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
