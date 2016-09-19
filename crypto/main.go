package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/adrienkohlbecker/ejson-kms/aws"
	"github.com/adrienkohlbecker/errors"
)

func Encrypt(kmsKeyArn string, plaintext []byte, context map[string]string) (string, errors.Error) {

	key, err := aws.GenerateDataKey(kmsKeyArn, context)
	if err != nil {
		return "", errors.WrapPrefix(err, "Unable to generate data key", 0)
	}

	ciphertext, err := encryptBytes(key.Plaintext, plaintext)
	if err != nil {
		return "", errors.WrapPrefix(err, "Unable to encrypt ciphertext", 0)
	}

	encoded := fmt.Sprintf("%s;%s;%s", magicPrefix, base64.StdEncoding.EncodeToString(key.Ciphertext), base64.StdEncoding.EncodeToString(ciphertext))

	return encoded, nil

}

func Decrypt(encoded string, context map[string]string) ([]byte, errors.Error) {

	decoded, err := decode(encoded)
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to decode ciphertext", 0)
	}

	key, err := aws.DecryptDataKey(decoded.keyCiphertext, context)
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to decrypt key ciphertext", 0)
	}

	plaintext, err := decryptBytes(key.Plaintext, decoded.ciphertext)
	if err != nil {
		return []byte{}, errors.WrapPrefix(err, "Unable to decrypt ciphertext", 0)
	}

	return plaintext, nil

}
