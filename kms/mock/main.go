package mock

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/mock"
)

type Client struct {
	mock.Mock
}

func (m *Client) GenerateDataKey(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

	args := m.Called(*params.KeyId, params.EncryptionContext)
	return &kms.GenerateDataKeyOutput{
		CiphertextBlob: []byte(args.String(0)),
		KeyId:          params.KeyId,
		Plaintext:      []byte(args.String(1)),
	}, args.Error(2)
}

func (m *Client) Decrypt(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

	args := m.Called(string(params.CiphertextBlob), params.EncryptionContext)
	keyID := args.String(0)
	return &kms.DecryptOutput{
		KeyId:     &keyID,
		Plaintext: []byte(args.String(1)),
	}, args.Error(2)

}
