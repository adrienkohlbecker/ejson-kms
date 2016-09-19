package crypto

import (
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/errors"
)

// Encrypt is the main entrypoint for encrypting credentials.
//
// It takes the ARN of the KMS key to use for data key generation, the plaintext
// to encrypt, the name of the credential (for logging purposes), and a key-value
// context to add to the generated key, and returns the encrypted and string
// encoded ciphertext.
//
// Note that the name of the credential is automatically added to the context
// under the key "credential"
func Encrypt(svc kms.KMS, kmsKeyArn string, plaintext []byte, name string, context map[string]*string) (string, errors.Error) {

	key, err := kms.GenerateDataKey(svc, kmsKeyArn, name, context)
	if err != nil {
		return "", err
	}

	ciphertext, err := EncryptBytes(key.Plaintext, plaintext)
	if err != nil {
		return "", err
	}

	msg := &Encrypted{Ciphertext: ciphertext, KeyCiphertext: key.Ciphertext}
	encoded := msg.Encode()

	return encoded, nil

}

// Decrypt is the main entrypoint for encrypting credentials.
// It takes the string-encoded ciphertext, the name of the credential
// (for logging purposes) and a key-value context that was added to the generated
// key for this credential, and returns the decoded and decrypted plaintext.
//
// Note that the name of the credential is automatically added to the context
// under the key "credential"
func Decrypt(svc kms.KMS, encoded string, name string, context map[string]*string) ([]byte, errors.Error) {

	decoded, err := Decode(encoded)
	if err != nil {
		return []byte{}, err
	}

	key, err := kms.DecryptDataKey(svc, decoded.KeyCiphertext, name, context)
	if err != nil {
		return []byte{}, err
	}

	plaintext, err := DecryptBytes(key.Plaintext, decoded.Ciphertext)
	if err != nil {
		return []byte{}, err
	}

	return plaintext, nil

}
