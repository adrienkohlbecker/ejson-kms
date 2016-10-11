package kms

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	kms_mock "github.com/adrienkohlbecker/ejson-kms/kms/mock"
	"github.com/stretchr/testify/assert"
)

var testContext = map[string]*string{"ABC": nil}

const (
	testKeyID         = "my-key-id"
	testKeyCiphertext = "ciphertextblob"
	testKeyPlaintext  = "plaintext"
)

func TestDummy(t *testing.T) {
	_ = DataKey{_hidden: struct{}{}}
}

func TestDefaultClient(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		s, err := DefaultClient()
		if assert.NoError(t, err) {
			assert.Implements(t, new(Client), s)
		}

	})

	t.Run("invalid", func(t *testing.T) {

		path, goErr := filepath.Abs("./testdata/invalid-aws")
		assert.NoError(t, goErr)

		goErr = os.Setenv("AWS_CONFIG_FILE", path)
		assert.NoError(t, goErr)
		goErr = os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
		assert.NoError(t, goErr)

		_, err := DefaultClient()
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to create AWS session")
		}

		goErr = os.Unsetenv("AWS_CONFIG_FILE")
		assert.NoError(t, goErr)
		goErr = os.Unsetenv("AWS_SDK_LOAD_CONFIG")
		assert.NoError(t, goErr)

	})

}

func TestGenerateDataKey(t *testing.T) {

	t.Run("without AWS error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("GenerateDataKey", testKeyID, testContext).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		expected := DataKey{
			Ciphertext: []byte(testKeyCiphertext),
			Plaintext:  []byte(testKeyPlaintext),
		}

		key, err := GenerateDataKey(client, testKeyID, testContext)
		assert.NoError(t, err)
		assert.Equal(t, key, expected)

	})

	t.Run("with AWS error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("GenerateDataKey", testKeyID, testContext).Return("", "", errors.New("testing errors")).Once()

		_, err := GenerateDataKey(client, testKeyID, testContext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to generate data key")
			assert.Contains(t, err.Error(), "testing errors")
		}

	})

}

func TestDecryptDataKey(t *testing.T) {

	t.Run("without AWS error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext).Return(testKeyID, testKeyPlaintext, nil).Once()

		expected := DataKey{
			Ciphertext: []byte(testKeyCiphertext),
			Plaintext:  []byte(testKeyPlaintext),
		}

		key, err := DecryptDataKey(client, []byte(testKeyCiphertext), testContext)
		assert.NoError(t, err)
		assert.Equal(t, key, expected)

	})

	t.Run("with AWS error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext).Return("", "", errors.New("testing errors")).Once()

		_, err := DecryptDataKey(client, []byte(testKeyCiphertext), testContext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt key ciphertext")
			assert.Contains(t, err.Error(), "testing errors")
		}

	})

}
