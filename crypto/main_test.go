package crypto

import (
	"errors"
	"testing"

	crypto_mock "github.com/adrienkohlbecker/ejson-kms/crypto/mock"
	kms_mock "github.com/adrienkohlbecker/ejson-kms/kms/mock"
	"github.com/stretchr/testify/assert"
)

var testContext = map[string]*string{"ABC": nil}

const testKeyID = "my-key-id"

const (
	testKeyPlaintext  = "-abcdefabcdefabcdefabcdefabcdef-"
	testKeyCiphertext = "ciphertextblob"
	testConstantNonce = "abcdefabcdefabcdefabcdef"
	testPlaintext     = "abcdef"
	testCiphertext    = "EJK1];Y2lwaGVydGV4dGJsb2I=;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmlPmP6IWfK7WJMuXVi8aQ7TZu8vCkVA=="
)

func TestEncrypt(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("GenerateDataKey", testKeyID, testContext).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		crypto_mock.WithConstRandReader(testConstantNonce, func() {

			cipher := NewCipher(client, testKeyID)
			encoded, err := cipher.Encrypt(testPlaintext, testContext)
			assert.NoError(t, err)
			assert.Equal(t, encoded, testCiphertext)

		})

	})

	t.Run("with aws error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("GenerateDataKey", testKeyID, testContext).Return("", "", errors.New("testing errors")).Once()

		cipher := NewCipher(client, testKeyID)
		_, err := cipher.Encrypt(testPlaintext, testContext)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to generate data key")

	})

	t.Run("with encrypt error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("GenerateDataKey", testKeyID, testContext).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		crypto_mock.WithErrorRandReader("testing error", func() {

			cipher := NewCipher(client, testKeyID)
			_, err := cipher.Encrypt(testPlaintext, testContext)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Unable to generate nonce")

		})

	})
}

func TestDecrypt(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext).Return(testKeyID, testKeyPlaintext, nil).Once()

		cipher := NewCipher(client, testKeyID)
		plaintext, err := cipher.Decrypt(testCiphertext, testContext)
		if assert.NoError(t, err) {
			assert.Equal(t, plaintext, testPlaintext)
		}

	})

	t.Run("with decode error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext).Return(testKeyID, testKeyPlaintext, nil).Once()

		cipher := NewCipher(client, testKeyID)
		_, err := cipher.Decrypt("abc", testContext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

	})

	t.Run("with aws error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext).Return("", "", errors.New("testing errors")).Once()

		cipher := NewCipher(client, testKeyID)
		_, err := cipher.Decrypt(testCiphertext, testContext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt key ciphertext")
		}

	})

	t.Run("with decrypt error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext).Return(testKeyID, "notlongenough", nil).Once()

		cipher := NewCipher(client, testKeyID)
		_, err := cipher.Decrypt(testCiphertext, testContext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Expected key size of 32, got 13")
		}

	})

}
