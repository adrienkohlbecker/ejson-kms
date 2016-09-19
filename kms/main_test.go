package kms

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
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

		mock := &MockKMS{}
		mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

			expected := &kms.GenerateDataKeyInput{
				KeyId:             aws.String("my-key-arn"),
				EncryptionContext: map[string]*string{"ABC": nil},
				GrantTokens:       []*string{},
				KeySpec:           aws.String("AES_256"),
			}

			assert.Equal(t, expected, params)

			return &kms.GenerateDataKeyOutput{
				CiphertextBlob: []byte("ciphertextblob"),
				KeyId:          aws.String("my-key-arn"),
				Plaintext:      []byte("plaintext"),
			}, nil

		}

		expected := DataKey{
			Ciphertext: []byte("ciphertextblob"),
			Plaintext:  []byte("plaintext"),
		}

		key, err := GenerateDataKey(mock, "my-key-arn", map[string]*string{"ABC": nil})
		assert.NoError(t, err)
		assert.Equal(t, key, expected)

	})

	t.Run("with AWS error", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
			return nil, fmt.Errorf("testing errors")
		}

		_, err := GenerateDataKey(mock, "my-key-arn", map[string]*string{"ABC": nil})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to generate data key")
			assert.Contains(t, err.Error(), "testing errors")
		}

	})

}

func TestDecryptDataKey(t *testing.T) {

	t.Run("without AWS error", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

			expected := &kms.DecryptInput{
				CiphertextBlob:    []byte("ciphertextblob"),
				EncryptionContext: map[string]*string{"ABC": nil},
				GrantTokens:       []*string{},
			}

			assert.Equal(t, expected, params)

			return &kms.DecryptOutput{
				KeyId:     aws.String("my-key-arn"),
				Plaintext: []byte("plaintext"),
			}, nil

		}

		expected := DataKey{
			Ciphertext: []byte("ciphertextblob"),
			Plaintext:  []byte("plaintext"),
		}

		key, err := DecryptDataKey(mock, []byte("ciphertextblob"), map[string]*string{"ABC": nil})
		assert.NoError(t, err)
		assert.Equal(t, key, expected)

	})

	t.Run("with AWS error", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
			return nil, fmt.Errorf("testing errors")
		}

		_, err := DecryptDataKey(mock, []byte("ciphertextblob"), map[string]*string{"ABC": nil})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt key ciphertext")
			assert.Contains(t, err.Error(), "testing errors")
		}

	})

}

type MockKMS struct {
	internalGenerateDataKey func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	internalDecrypt         func(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

func (m *MockKMS) GenerateDataKey(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	return m.internalGenerateDataKey(params)
}
func (m *MockKMS) Decrypt(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return m.internalDecrypt(params)
}
