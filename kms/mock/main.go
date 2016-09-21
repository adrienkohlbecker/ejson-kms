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

func New(t *testing.T, testKeyID string, testEncryptionContext map[string]*string, testKeyCiphertext string, testKeyPlaintext string) *Client {

	mock := &Client{}
	mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

		expected := &kms.GenerateDataKeyInput{
			KeyId:             aws.String(testKeyID),
			EncryptionContext: testEncryptionContext,
			GrantTokens:       []*string{},
			KeySpec:           aws.String("AES_256"),
		}

		assert.Equal(t, expected, params)

		return &kms.GenerateDataKeyOutput{
			CiphertextBlob: []byte(testKeyCiphertext),
			KeyId:          aws.String(testKeyID),
			Plaintext:      []byte(testKeyPlaintext),
		}, nil

	}
	mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

		expected := &kms.DecryptInput{
			CiphertextBlob:    []byte(testKeyCiphertext),
			EncryptionContext: testEncryptionContext,
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

func NewWithError(testError string) *Client {

	mock := &Client{}
	mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
		return nil, fmt.Errorf(testError)
	}
	mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
		return nil, fmt.Errorf(testError)
	}

	return mock

}
