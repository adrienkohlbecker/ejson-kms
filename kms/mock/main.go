package mock

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/mock"
)

// Client is an implementation of kms.KMS with mock capabilities
type Client struct {
	mock.Mock
}

// GenerateDataKey is meant to replace kms.GenerateDataKey
//
//   client := &mock.Client{}
//   client.On("GenerateDataKey", testKeyID, testContext).Return(testKeyCiphertext, testKeyPlaintext, nil)
//
func (m *Client) GenerateDataKey(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

	if len(params.GrantTokens) > 0 || *params.KeySpec != "AES_256" {
		panic("unexpected arguments to GenerateDataKey")
	}

	args := m.Called(*params.KeyId, params.EncryptionContext)
	return &kms.GenerateDataKeyOutput{
		CiphertextBlob: []byte(args.String(0)),
		KeyId:          params.KeyId,
		Plaintext:      []byte(args.String(1)),
	}, args.Error(2)
}

// Decrypt is meant to replace kms.Decrypt
//
//   client := &mock.Client{}
//   client.On("Decrypt", testKeyCiphertext, testContext).Return(testKeyID, testKeyPlaintext, nil)
//
func (m *Client) Decrypt(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

	if len(params.GrantTokens) > 0 {
		panic("unexpected arguments to Decrypt")
	}

	args := m.Called(string(params.CiphertextBlob), params.EncryptionContext)
	keyID := args.String(0)
	return &kms.DecryptOutput{
		KeyId:     &keyID,
		Plaintext: []byte(args.String(1)),
	}, args.Error(2)

}
