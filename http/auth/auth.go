package auth

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Changing any part of this configuration will break existing passwords
var params = struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}{
	memory:      64 * 1024,
	iterations:  10,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

func NewArgon2Hash(password string) (salt, hash []byte, err error) {
	salt, err = GenerateRandomBytes(params.saltLength)
	if err != nil {
		return nil, nil, err
	}

	hash = argon2.IDKey([]byte(password), salt,
		params.iterations, params.memory, params.parallelism, params.keyLength)

	return salt, hash, nil
}

var ErrSaltSize = fmt.Errorf("salt must be exactly %d bytes", params.saltLength)

func HashArgon2(password string, salt []byte) ([]byte, error) {
	if len(salt) != int(params.saltLength) {
		return nil, ErrSaltSize
	}

	hash := argon2.IDKey([]byte(password), salt,
		params.iterations, params.memory, params.parallelism, params.keyLength)

	return hash, nil
}

func GenerateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
