package crypto

import (
	"github.com/adrienkohlbecker/ejson-kms/kms"
)

// Cipher is a struct containing the configuration for crypto operations on
// a single secrets file.
type Cipher struct {
	// _hidden is a dummy hidden key to force the use of explicit keys when
	// initializing the struct. Allows adding keys in the future without
	// breaking code
	_hidden struct{}

	// Client is the AWS KMS client
	Client kms.Client

	// KMSKeyID is the ID of the master key to use for key wrapping
	KMSKeyID string
}

// NewCipher returns an initialized Cipher.
func NewCipher(client kms.Client, kmsKeyID string) *Cipher {
	return &Cipher{
		Client:   client,
		KMSKeyID: kmsKeyID,
	}
}

// Encrypt is the main entrypoint for encrypting secrets.
//
// It takes the plaintext to encrypt, and returns the encrypted
// and string-encoded ciphertext.
func (c *Cipher) Encrypt(plaintext string, context map[string]*string) (string, error) {

	key, err := kms.GenerateDataKey(c.Client, c.KMSKeyID, context)
	if err != nil {
		return "", err
	}

	ciphertext, err := encryptBytes(key.Plaintext, []byte(plaintext))
	if err != nil {
		return "", err
	}

	encrypted := &encrypted{keyCiphertext: key.Ciphertext, ciphertext: ciphertext}
	return encrypted.encode(), nil

}

// Decrypt is the main entrypoint for encrypting secrets.
//
// It takes the string-encoded ciphertext and returns the decoded
// and decrypted plaintext.
func (c *Cipher) Decrypt(encoded string, context map[string]*string) (string, error) {

	encrypted, err := decode(encoded)
	if err != nil {
		return "", err
	}

	key, err := kms.DecryptDataKey(c.Client, encrypted.keyCiphertext, context)
	if err != nil {
		return "", err
	}

	plaintext, err := decryptBytes(key.Plaintext, encrypted.ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil

}
