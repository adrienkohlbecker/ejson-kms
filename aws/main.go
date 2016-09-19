package aws

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

func GenerateDataKey(kmsKeyArn string, context map[string]string) (DataKey, errors.Error) {

	sess, err := session.NewSession()
	if err != nil {
		return DataKey{}, errors.WrapPrefix(err, "Failed to create AWS session", 0)
	}

	svc := kms.New(sess)

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

func DecryptDataKey(ciphertext []byte, context map[string]string) (DataKey, errors.Error) {

	sess, err := session.NewSession()
	if err != nil {
		return DataKey{}, errors.WrapPrefix(err, "Failed to create AWS session", 0)
	}

	svc := kms.New(sess)

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
