package kms

import (
	"github.com/adrienkohlbecker/errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type DataKey struct {
	Ciphertext []byte
	Plaintext  []byte
}

type KMS interface {
	GenerateDataKey(*kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

func Service() (KMS, errors.Error) {

	sess, err := session.NewSession()
	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to create AWS session", 0)
	}

	return kms.New(sess), nil

}

func GenerateDataKey(svc KMS, kmsKeyArn string, context map[string]string) (DataKey, errors.Error) {

	awsContext := make(map[string]*string)
	for key, value := range context {
		awsContext[key] = aws.String(value)
	}

	params := &kms.GenerateDataKeyInput{
		KeyId:             aws.String(kmsKeyArn), // Required
		EncryptionContext: awsContext,
		GrantTokens:       []*string{},
		KeySpec:           aws.String("AES_256"),
	}

	resp, err := svc.GenerateDataKey(params)
	if err != nil {
		return DataKey{}, errors.WrapPrefix(err, "Unable to generate data key", 0)
	}

	return DataKey{Ciphertext: resp.CiphertextBlob, Plaintext: resp.Plaintext}, nil

}

func DecryptDataKey(svc KMS, ciphertext []byte, context map[string]string) (DataKey, errors.Error) {

	awsContext := make(map[string]*string)
	for key, value := range context {
		awsContext[key] = aws.String(value)
	}

	params := &kms.DecryptInput{
		CiphertextBlob:    ciphertext,
		EncryptionContext: awsContext,
		GrantTokens:       []*string{},
	}

	resp, err := svc.Decrypt(params)
	if err != nil {
		return DataKey{}, errors.WrapPrefix(err, "Unable to decrypt key ciphertext", 0)
	}

	return DataKey{Ciphertext: ciphertext, Plaintext: resp.Plaintext}, nil

}
