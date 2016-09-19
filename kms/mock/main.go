package mock

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
)

type Mock struct {
	internalGenerateDataKey func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	internalDecrypt         func(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

func (m *Mock) GenerateDataKey(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	return m.internalGenerateDataKey(params)
}
func (m *Mock) Decrypt(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return m.internalDecrypt(params)
}

func MockGenerateDataKey(t *testing.T, kmsKeyARN string, context map[string]*string, keyCiphertext string, keyPlaintext string) *Mock {

	mock := &Mock{}
	mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {

		expected := &kms.GenerateDataKeyInput{
			KeyId:             aws.String(kmsKeyARN),
			EncryptionContext: context,
			GrantTokens:       []*string{},
			KeySpec:           aws.String("AES_256"),
		}

		assert.Equal(t, expected, params)

		return &kms.GenerateDataKeyOutput{
			CiphertextBlob: []byte(keyCiphertext),
			KeyId:          aws.String(kmsKeyARN),
			Plaintext:      []byte(keyPlaintext),
		}, nil

	}

	return mock

}

func MockGenerateDataKeyWithError(str string) *Mock {

	mock := &Mock{}
	mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
		return nil, fmt.Errorf(str)
	}

	return mock

}

func MockDecrypt(t *testing.T, testKeyARN string, testContext map[string]*string, testKeyCiphertext string, testKeyPlaintext string) *Mock {

	mock := &Mock{}
	mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {

		expected := &kms.DecryptInput{
			CiphertextBlob:    []byte(testKeyCiphertext),
			EncryptionContext: testContext,
			GrantTokens:       []*string{},
		}

		assert.Equal(t, expected, params)

		return &kms.DecryptOutput{
			KeyId:     aws.String(testKeyARN),
			Plaintext: []byte(testKeyPlaintext),
		}, nil

	}

	return mock
}

func MockDecryptWithError(str string) *Mock {
	mock := &Mock{}
	mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
		return nil, fmt.Errorf(str)
	}
	return mock
}
