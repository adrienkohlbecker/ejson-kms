package mock

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
)

type KMS struct {
	internalGenerateDataKey func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	internalDecrypt         func(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

func (m *KMS) GenerateDataKey(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	return m.internalGenerateDataKey(params)
}
func (m *KMS) Decrypt(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return m.internalDecrypt(params)
}

func GenerateDataKey(t *testing.T, kmsKeyARN string, context map[string]*string, keyCiphertext string, keyPlaintext string) *KMS {

	mock := &KMS{}
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

func GenerateDataKeyWithError(str string) *KMS {

	mock := &KMS{}
	mock.internalGenerateDataKey = func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
		return nil, fmt.Errorf(str)
	}

	return mock

}

func Decrypt(t *testing.T, testKeyARN string, testContext map[string]*string, testKeyCiphertext string, testKeyPlaintext string) *KMS {

	mock := &KMS{}
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

func DecryptWithError(str string) *KMS {
	mock := &KMS{}
	mock.internalDecrypt = func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
		return nil, fmt.Errorf(str)
	}
	return mock
}
