package crypto

import (
	"crypto/rand"
	"io"

	"github.com/adrienkohlbecker/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

const nonceSize = 24
const keySize = 32

func nonce() ([nonceSize]byte, errors.Error) {

	nonce := [nonceSize]byte{}

	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return [nonceSize]byte{}, errors.WrapPrefix(err, "Unable to generate nonce", 0)
	}

	return nonce, nil

}

func encryptBytes(keyBytes []byte, plaintext []byte) ([]byte, errors.Error) {

	if len(keyBytes) != keySize {
		return []byte{}, errors.Errorf("Expected key size of %d, got %d", keySize, len(keyBytes))
	}

	var key [keySize]byte
	copy(key[:], keyBytes[:keySize])

	nonce, err := nonce()
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to generate nonce", 0)
	}

	ciphertext := secretbox.Seal(nonce[:], plaintext, &nonce, &key)

	return ciphertext, nil

}

func decryptBytes(keyBytes []byte, bytes []byte) ([]byte, errors.Error) {

	if len(keyBytes) != keySize {
		return []byte{}, errors.Errorf("Expected key size of %d, got %d", keySize, len(keyBytes))
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
