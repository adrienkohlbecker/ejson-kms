package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type errorReader struct{}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("testing error")
}

func TestNonce(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		nonce, err := Nonce()
		assert.NoError(t, err)
		assert.Equal(t, NonceSize, len(nonce))

	})

	t.Run("failing", func(t *testing.T) {

		original := rand.Reader
		rand.Reader = &errorReader{}

		_, err := Nonce()
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to generate nonce")
		}

		rand.Reader = original

	})

}

func TestEncryptBytes(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		keyBytes := []byte("-abcdefabcdefabcdefabcdefabcdef-")
		plaintext := []byte("plaintext")
		ciphertext, err := EncryptBytes(keyBytes, plaintext)
		assert.NoError(t, err)
		assert.NotEmpty(t, ciphertext)

	})

	t.Run("incorrect key size", func(t *testing.T) {

		keyBytes := []byte("abcdef")
		plaintext := []byte("plaintext")
		_, err := EncryptBytes(keyBytes, plaintext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Expected key size of 32, got 6")
		}

	})

	t.Run("nonce error", func(t *testing.T) {

		original := rand.Reader
		rand.Reader = &errorReader{}

		keyBytes := []byte("-abcdefabcdefabcdefabcdefabcdef-")
		plaintext := []byte("plaintext")
		_, err := EncryptBytes(keyBytes, plaintext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to generate nonce")
		}

		rand.Reader = original

	})

}

func TestDecryptBytes(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		ciphertext := []byte("fV\x12,\x18\x9cd\xc2\xcbp/\xf1e\xd9}\xd6%j\x05Q\xc7\x1e\xf5\x99\xf8f\xe1\x99=G\x8dp\xb0\xf7\xca\xc8++Կ\x06\xe7i'\xa0\xb6}x\xa6")
		keyBytes := []byte("-abcdefabcdefabcdefabcdefabcdef-")

		plaintext, err := DecryptBytes(keyBytes, ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, []byte(plaintext))

	})

	t.Run("incorrect key size", func(t *testing.T) {

		ciphertext := []byte("fV\x12,\x18\x9cd\xc2\xcbp/\xf1e\xd9}\xd6%j\x05Q\xc7\x1e\xf5\x99\xf8f\xe1\x99=G\x8dp\xb0\xf7\xca\xc8++Կ\x06\xe7i'\xa0\xb6}x\xa6")
		keyBytes := []byte("abcdef")

		_, err := DecryptBytes(keyBytes, ciphertext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Expected key size of 32, got 6")
		}

	})

	t.Run("invalid ciphertext", func(t *testing.T) {

		ciphertext := []byte("abcdef")
		keyBytes := []byte("-abcdefabcdefabcdefabcdefabcdef-")

		_, err := DecryptBytes(keyBytes, ciphertext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid ciphertext")
		}

	})

	t.Run("corrupted ciphertext", func(t *testing.T) {

		ciphertext := []byte("-abcdefabcdefabcdefabcdefabcdef-")
		keyBytes := []byte("-abcdefabcdefabcdefabcdefabcdef-")

		_, err := DecryptBytes(keyBytes, ciphertext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt ciphertext")
		}

	})

}
