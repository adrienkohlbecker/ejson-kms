package mock

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
)

type Client struct {
	internalGenerateDataKey func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	internalDecrypt         func(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

func (m *Client) GenerateDataKey(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	return m.internalGenerateDataKey(params)
}
func (m *Client) Decrypt(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return m.internalDecrypt(params)
}

func GenerateDataKey(t *testing.T, kmsKeyID string, encryptionContext map[string]*string, keyCiphertext string, keyPlaintext string) *Client {

	mock := &Client{}
	mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

		expected := &kms.GenerateDataKeyInput{
			KeyId:             aws.String(kmsKeyID),
			EncryptionContext: encryptionContext,
			GrantTokens:       []*string{},
			KeySpec:           aws.String("AES_256"),
		}

		assert.Equal(t, expected, params)

		return &kms.GenerateDataKeyOutput{
			CiphertextBlob: []byte(keyCiphertext),
			KeyId:          aws.String(kmsKeyID),
			Plaintext:      []byte(keyPlaintext),
		}, nil

	}

	return mock

}

func GenerateDataKeyWithError(str string) *Client {

	mock := &Client{}
	mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
		return nil, fmt.Errorf(str)
	}

	return mock

}

func Decrypt(t *testing.T, testKeyID string, testContext map[string]*string, testKeyCiphertext string, testKeyPlaintext string) *Client {

	mock := &Client{}
	mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

		expected := &kms.DecryptInput{
			CiphertextBlob:    []byte(testKeyCiphertext),
			EncryptionContext: testContext,
			GrantTokens:       []*string{},
		}

		assert.Equal(t, expected, params)

		return &kms.DecryptOutput{
			KeyId:     aws.String(testKeyID),
			Plaintext: []byte(testKeyPlaintext),
		}, nil

	}

	return mock
}

func DecryptWithError(str string) *Client {
	mock := &Client{}
	mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
		return nil, fmt.Errorf(str)
	}
	return mock
}
