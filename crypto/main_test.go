package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
)

type constReader struct{}

func (r *constReader) Read(p []byte) (n int, err error) {
	copy(p[:], []byte("abcdefabcdefabcdefabcdef"))
	return 24, nil
}

func TestEncrypt(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

			expected := &kms.GenerateDataKeyInput{
				KeyId:             aws.String("my-key-arn"),
				EncryptionContext: map[string]*string{"ABC": nil, "credential": aws.String("my_cred")},
				GrantTokens:       []*string{},
				KeySpec:           aws.String("AES_256"),
			}

			assert.Equal(t, expected, params)

			return &kms.GenerateDataKeyOutput{
				CiphertextBlob: []byte("ciphertextblob"),
				KeyId:          aws.String("my-key-arn"),
				Plaintext:      []byte("-abcdefabcdefabcdefabcdefabcdef-"),
			}, nil

		}

		original := rand.Reader
		rand.Reader = &constReader{}

		encoded, err := Encrypt(mock, "my-key-arn", []byte("abcdef"), "my_cred", map[string]*string{"ABC": nil})
		assert.NoError(t, err)
		assert.Equal(t, encoded, "EJK1];Y2lwaGVydGV4dGJsb2I=;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmlPmP6IWfK7WJMuXVi8aQ7TZu8vCkVA==")

		rand.Reader = original
	})

	t.Run("with aws error", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
			return nil, fmt.Errorf("testing errors")
		}

		_, err := Encrypt(mock, "my-key-arn", []byte("abcdef"), "my_cred", map[string]*string{"ABC": nil})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to generate data key")

	})

	t.Run("with encrypt error", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

			expected := &kms.GenerateDataKeyInput{
				KeyId:             aws.String("my-key-arn"),
				EncryptionContext: map[string]*string{"ABC": nil, "credential": aws.String("my_cred")},
				GrantTokens:       []*string{},
				KeySpec:           aws.String("AES_256"),
			}

			assert.Equal(t, expected, params)

			return &kms.GenerateDataKeyOutput{
				CiphertextBlob: []byte("ciphertextblob"),
				KeyId:          aws.String("my-key-arn"),
				Plaintext:      []byte("-abcdefabcdefabcdefabcdefabcdef-"),
			}, nil

		}

		original := rand.Reader
		rand.Reader = &errorReader{}

		_, err := Encrypt(mock, "my-key-arn", []byte("abcdef"), "my_cred", map[string]*string{"ABC": nil})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to generate nonce")

		rand.Reader = original
	})

}

func TestDecrypt(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

			expected := &kms.DecryptInput{
				CiphertextBlob:    []byte("ciphertextblob"),
				EncryptionContext: map[string]*string{"ABC": nil, "credential": aws.String("my_cred")},
				GrantTokens:       []*string{},
			}

			assert.Equal(t, expected, params)

			return &kms.DecryptOutput{
				KeyId:     aws.String("my-key-arn"),
				Plaintext: []byte("-abcdefabcdefabcdefabcdefabcdef-"),
			}, nil

		}

		plaintext, err := Decrypt(mock, "EJK1];Y2lwaGVydGV4dGJsb2I=;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmlPmP6IWfK7WJMuXVi8aQ7TZu8vCkVA==", "my_cred", map[string]*string{"ABC": nil})
		if assert.NoError(t, err) {
			assert.Equal(t, plaintext, []byte("abcdef"))
		}

	})

	t.Run("with decode error", func(t *testing.T) {

		mock := &MockKMS{}
		_, err := Decrypt(mock, "abc", "my_cred", map[string]*string{"ABC": nil})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

	})

	t.Run("with aws error", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
			return nil, fmt.Errorf("testing errors")
		}

		_, err := Decrypt(mock, "EJK1];Y2lwaGVydGV4dGJsb2I=;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmlPmP6IWfK7WJMuXVi8aQ7TZu8vCkVA==", "my_cred", map[string]*string{"ABC": nil})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt key ciphertext")
		}

	})

	t.Run("with decrypt error", func(t *testing.T) {

		mock := &MockKMS{}
		mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

			expected := &kms.DecryptInput{
				CiphertextBlob:    []byte("ciphertextblob"),
				EncryptionContext: map[string]*string{"ABC": nil, "credential": aws.String("my_cred")},
				GrantTokens:       []*string{},
			}

			assert.Equal(t, expected, params)

			return &kms.DecryptOutput{
				KeyId:     aws.String("my-key-arn"),
				Plaintext: []byte("notlongenough"),
			}, nil

		}

		_, err := Decrypt(mock, "EJK1];Y2lwaGVydGV4dGJsb2I=;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmlPmP6IWfK7WJMuXVi8aQ7TZu8vCkVA==", "my_cred", map[string]*string{"ABC": nil})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Expected key size of 32, got 13")
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
