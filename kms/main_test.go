package kms

import (
	"os"
	"path/filepath"
	"testing"

	kms_mock "github.com/adrienkohlbecker/ejson-kms/kms/mock"
	"github.com/stretchr/testify/assert"
)

var testContext = map[string]*string{"ABC": nil}

const (
	testKeyARN        = "my-key-arn"
	testKeyCiphertext = "ciphertextblob"
	testKeyPlaintext  = "plaintext"
)

func TestService(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		s, err := Service()
		if assert.NoError(t, err) {
			assert.Implements(t, new(KMS), s)
		}

	})

	t.Run("invalid", func(t *testing.T) {

		path, goErr := filepath.Abs("./testdata/invalid-aws")
		assert.NoError(t, goErr)

		goErr = os.Setenv("AWS_CONFIG_FILE", path)
		assert.NoError(t, goErr)
		goErr = os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
		assert.NoError(t, goErr)

		_, err := Service()
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

		svc := kms_mock.MockGenerateDataKey(t, testKeyARN, testContext, testKeyCiphertext, testKeyPlaintext)

		expected := DataKey{
			Ciphertext: []byte(testKeyCiphertext),
			Plaintext:  []byte(testKeyPlaintext),
		}

		key, err := GenerateDataKey(svc, testKeyARN, testContext)
		assert.NoError(t, err)
		assert.Equal(t, key, expected)

	})

	t.Run("with AWS error", func(t *testing.T) {

		svc := kms_mock.MockGenerateDataKeyWithError("testing errors")

		_, err := GenerateDataKey(svc, testKeyARN, testContext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to generate data key")
			assert.Contains(t, err.Error(), "testing errors")
		}

	})

}

func TestDecryptDataKey(t *testing.T) {

	t.Run("without AWS error", func(t *testing.T) {

		svc := kms_mock.MockDecrypt(t, testKeyARN, testContext, testKeyCiphertext, testKeyPlaintext)

		expected := DataKey{
			Ciphertext: []byte(testKeyCiphertext),
			Plaintext:  []byte(testKeyPlaintext),
		}

		key, err := DecryptDataKey(svc, []byte(testKeyCiphertext), testContext)
		assert.NoError(t, err)
		assert.Equal(t, key, expected)

	})

	t.Run("with AWS error", func(t *testing.T) {

		svc := kms_mock.MockDecryptWithError("testing errors")

		_, err := DecryptDataKey(svc, []byte(testKeyCiphertext), testContext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt key ciphertext")
			assert.Contains(t, err.Error(), "testing errors")
		}

	})

}
