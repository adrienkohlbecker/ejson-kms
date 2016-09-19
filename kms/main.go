package kms

import (
	"github.com/adrienkohlbecker/errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// DataKey is a structure used to hold the ciphertext and plaintext of
// a generated KMS data key.
type DataKey struct {
	Ciphertext []byte
	Plaintext  []byte
}

// KMS is the interface that is implemented by kms.KMS.
type KMS interface {
	GenerateDataKey(*kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

// Service creates a new AWS session (reads credentials and settings from
// the environment), and returns a ready-to-use KMS instance.
func Service() (KMS, errors.Error) {

	sess, err := session.NewSession()
	if err != nil {
		return nil, errors.WrapPrefix(err, "Unable to create AWS session", 0)
	}

	return kms.New(sess), nil

}

// GenerateDataKey creates a encryption key that can be use to locally encrypt
// data. The key length is 256 bits. It returns both the plaintext of the key
// for immediate use, and it's encrypted version using the KMS master key for
// storage.
//
// A context can be given as key-value pairs. These are stored with the key,
// logged through AWS CloudTrail (if enabled), and must be provided as is
// for each future use of the data key.
func GenerateDataKey(svc KMS, kmsKeyArn string, context map[string]*string) (DataKey, errors.Error) {

	params := &kms.GenerateDataKeyInput{
		KeyId:             aws.String(kmsKeyArn),
		EncryptionContext: context,
		GrantTokens:       []*string{},
		KeySpec:           aws.String("AES_256"), // to generate a 32 bytes key for secretbox
	}

	resp, err := svc.GenerateDataKey(params)
	if err != nil {
		return DataKey{}, errors.WrapPrefix(err, "Unable to generate data key", 0)
	}

	return DataKey{Ciphertext: resp.CiphertextBlob, Plaintext: resp.Plaintext}, nil

}

// DecryptDataKey takes an encrypted data key and associated context, and
// returns the key plaintext (along with the ciphertext for consistency).
func DecryptDataKey(svc KMS, ciphertext []byte, context map[string]*string) (DataKey, errors.Error) {

	params := &kms.DecryptInput{
		CiphertextBlob:    ciphertext,
		EncryptionContext: context,
		GrantTokens:       []*string{},
	}

	resp, err := svc.Decrypt(params)
	if err != nil {
		return DataKey{}, errors.WrapPrefix(err, "Unable to decrypt key ciphertext", 0)
	}

	return DataKey{Ciphertext: ciphertext, Plaintext: resp.Plaintext}, nil

}
