package crypto

import (
	"crypto/rand"
	"io"

	"github.com/adrienkohlbecker/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

// Constants for input sizes with nacl/secretbox
const (
	NonceSize = 24
	KeySize   = 32
)

// Nonce generates a random nonce using a cryptographically secure random source.
//
// From crypto/rand documentation:
//
//   On Linux, Reader uses getrandom(2) if available, /dev/urandom otherwise.
//   On OpenBSD, Reader uses getentropy(2).
//   On other Unix-like systems, Reader reads from /dev/urandom.
//   On Windows systems, Reader uses the CryptGenRandom API.
func Nonce() ([NonceSize]byte, errors.Error) {

	nonce := [NonceSize]byte{}

	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return [NonceSize]byte{}, errors.WrapPrefix(err, "Unable to generate nonce", 0)
	}

	return nonce, nil

}

// EncryptBytes uses nacl/secretbox to encrypt a plaintext. A random nonce
// is generated for each call. The return value is the nonce + ciphertext
// in a single byte slice.
func EncryptBytes(keyBytes []byte, plaintext []byte) ([]byte, errors.Error) {

	if len(keyBytes) != KeySize {
		return []byte{}, errors.Errorf("Expected key size of %d, got %d", KeySize, len(keyBytes))
	}

	var key [KeySize]byte
	copy(key[:], keyBytes[:KeySize])

	nonce, err := Nonce()
	if err != nil {
		return []byte{}, err
	}

	ciphertext := secretbox.Seal(nonce[:], plaintext, &nonce, &key)

	return ciphertext, nil

}

// DecryptBytes uses nacl/secretbox to decrypt a ciphertext. The input must
// take the form nonce + ciphertext in a single byte slice.
func DecryptBytes(keyBytes []byte, bytes []byte) ([]byte, errors.Error) {

	if len(keyBytes) != KeySize {
		return []byte{}, errors.Errorf("Expected key size of %d, got %d", KeySize, len(keyBytes))
	}

	if len(bytes) < KeySize {
		return []byte{}, errors.Errorf("Invalid ciphertext")
	}

	var key [KeySize]byte
	copy(key[:], keyBytes[:KeySize])

	var nonce [NonceSize]byte
	copy(nonce[:], bytes[:NonceSize])

	ciphertext := bytes[NonceSize:]

	plaintext, ok := secretbox.Open([]byte{}, ciphertext, &nonce, &key)
	if !ok {
		return []byte{}, errors.Errorf("Unable to decrypt ciphertext")
	}

	return plaintext, nil

}
