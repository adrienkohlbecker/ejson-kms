package crypto

import (
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/errors"
)

// Cipher is a struct containing the configuration for crypto operations on
// a single credentials file.
type Cipher struct {
	// Svc is the AWS KMS client
	Svc kms.KMS

	// KmsKeyArn is the ARN of the master key to use for key wrapping
	KmsKeyArn string

	// Context is a key-value store of arbitrary values added to the data keys
	Context map[string]*string
}

// NewCipher returns an initialized Cipher.
func NewCipher(svc kms.KMS, kmsKeyArn string, context map[string]*string) *Cipher {
	return &Cipher{
		Svc:       svc,
		KmsKeyArn: kmsKeyArn,
		Context:   context,
	}
}

// Encrypt is the main entrypoint for encrypting credentials.
//
// It takes the plaintext to encrypt, and returns the encrypted
// and string-encoded ciphertext.
func (c *Cipher) Encrypt(plaintext string) (string, errors.Error) {

	key, err := kms.GenerateDataKey(c.Svc, c.KmsKeyArn, c.Context)
	if err != nil {
		return "", err
	}

	ciphertext, err := EncryptBytes(key.Plaintext, []byte(plaintext))
	if err != nil {
		return "", err
	}

	msg := &Encrypted{Ciphertext: ciphertext, KeyCiphertext: key.Ciphertext}
	encoded := msg.Encode()

	return encoded, nil

}

// Decrypt is the main entrypoint for encrypting credentials.
//
// It takes the string-encoded ciphertext and returns the decoded
// and decrypted plaintext.
func (c *Cipher) Decrypt(encoded string) (string, errors.Error) {

	decoded, err := Decode(encoded)
	if err != nil {
		return "", err
	}

	key, err := kms.DecryptDataKey(c.Svc, decoded.KeyCiphertext, c.Context)
	if err != nil {
		return "", err
	}

	plaintext, err := DecryptBytes(key.Plaintext, decoded.Ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil

}
