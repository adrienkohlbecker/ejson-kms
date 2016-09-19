package crypto

import (
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/errors"
)

func Encrypt(svc kms.KMS, kmsKeyArn string, plaintext []byte, context map[string]*string) (string, errors.Error) {

	key, err := kms.GenerateDataKey(svc, kmsKeyArn, context)
	if err != nil {
		return "", err
	}

	ciphertext, err := encryptBytes(key.Plaintext, plaintext)
	if err != nil {
		return "", err
	}

	encoded := encode(msg{ciphertext: ciphertext, keyCiphertext: key.Ciphertext})

	return encoded, nil

}

func Decrypt(svc kms.KMS, encoded string, context map[string]*string) ([]byte, errors.Error) {

	decoded, err := decode(encoded)
	if err != nil {
		return []byte{}, err
	}

	key, err := kms.DecryptDataKey(svc, decoded.keyCiphertext, context)
	if err != nil {
		return []byte{}, err
	}

	plaintext, err := decryptBytes(key.Plaintext, decoded.ciphertext)
	if err != nil {
		return []byte{}, err
	}

	return plaintext, nil

}
