package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/adrienkohlbecker/errors"
)

func aesgcm(key []byte) (cipher.AEAD, errors.Error) {

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Unable to initialize AES cipher", 0)
	}

	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Unable to initialize GCM cipher", 0)
	}

	return aead, nil

}

func nonce(size int) ([]byte, errors.Error) {

	nonce := make([]byte, size)

	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to generate nonce", 0)
	}

	return nonce, nil

}

func encryptBytes(key []byte, plaintext []byte) ([]byte, errors.Error) {

	aead, err := aesgcm(key)
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to initialize AES-GCM cipher", 0)
	}

	nonce, err := nonce(aead.NonceSize())
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to generate nonce", 0)
	}

	ciphertext := aead.Seal([]byte{}, nonce, plaintext, []byte{})

	return append(nonce, ciphertext...), nil

}

func decryptBytes(key []byte, bytes []byte) ([]byte, errors.Error) {

	aead, err := aesgcm(key)
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to initialize AES-GCM cipher", 0)
	}

	nonceSize := aead.NonceSize()

	nonce := bytes[:nonceSize]
	ciphertext := bytes[nonceSize:]

	plaintext, goErr := aead.Open([]byte{}, nonce, ciphertext, []byte{})
	if goErr != nil {
		return []byte{}, errors.WrapPrefix(goErr, "Unable to decrypt ciphertext", 0)
	}

	return plaintext, nil

}
