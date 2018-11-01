package crypto

import (
	"crypto/rand"
	"io"

	"github.com/go-errors/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

// Constants for input sizes with nacl/secretbox
const (
	nonceSize = 24
	keySize   = 32
)

// randomNonce generates a random nonce using a cryptographically secure random source.
//
// From crypto/rand documentation:
//
//   On Linux, Reader uses getrandom(2) if available, /dev/urandom otherwise.
//   On OpenBSD, Reader uses getentropy(2).
//   On other Unix-like systems, Reader reads from /dev/urandom.
//   On Windows systems, Reader uses the CryptGenRandom API.
func randomNonce() ([nonceSize]byte, error) {

	nonce := [nonceSize]byte{}

	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return [nonceSize]byte{}, errors.WrapPrefix(err, "Unable to generate nonce", 0)
	}

	return nonce, nil

}

// encryptBytes uses nacl/secretbox to encrypt a plaintext. A random nonce
// is generated for each call. The return value is the nonce + ciphertext
// in a single byte slice.
func encryptBytes(keyBytes []byte, plaintext []byte) ([]byte, error) {

	if len(keyBytes) != keySize {
		return []byte{}, errors.Errorf("Expected key size of %d, got %d", keySize, len(keyBytes))
	}

	var key [keySize]byte
	copy(key[:], keyBytes[:keySize])

	nonce, err := randomNonce()
	if err != nil {
		return []byte{}, err
	}

	ciphertext := secretbox.Seal(nonce[:], plaintext, &nonce, &key)

	return ciphertext, nil

}

// decryptBytes uses nacl/secretbox to decrypt a ciphertext. The input must
// take the form nonce + ciphertext in a single byte slice.
func decryptBytes(keyBytes []byte, bytes []byte) ([]byte, error) {

	if len(keyBytes) != keySize {
		return []byte{}, errors.Errorf("Expected key size of %d, got %d", keySize, len(keyBytes))
	}

	if len(bytes) < keySize {
		return []byte{}, errors.Errorf("Invalid ciphertext")
	}

	var key [keySize]byte
	copy(key[:], keyBytes[:keySize])

	var nonce [nonceSize]byte
	copy(nonce[:], bytes[:nonceSize])

	ciphertext := bytes[nonceSize:]

	plaintext, ok := secretbox.Open([]byte{}, ciphertext, &nonce, &key)
	if !ok {
		return []byte{}, errors.Errorf("Unable to decrypt ciphertext")
	}

	return plaintext, nil

}
