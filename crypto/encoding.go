package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-errors/errors"
)

// MagicPrefix is a string prepended to all ciphertexts in the JSON representation.
// It will allow versioning the algorithm in the future.
const MagicPrefix = "EJK1"

// encrypted is a struct representation of a encrypted secret.
// It contains the ciphertext of both the secret and the data key.
type encrypted struct {
	ciphertext    []byte
	keyCiphertext []byte
}

// encode takes a raw message and encodes it for the JSON representation.
// The format is:
//
//   magicPrefix + ";" + base64(keyCiphertext) + ";" + base64(ciphertext)
func (encoded *encrypted) encode() string {
	return fmt.Sprintf("%s;%s;%s", MagicPrefix, base64.StdEncoding.EncodeToString(encoded.keyCiphertext), base64.StdEncoding.EncodeToString(encoded.ciphertext))
}

// decode takes a string from the JSON representation and decodes the
// ciphertext and keyCiphertext, while validating the format.
func decode(encoded string) (*encrypted, error) {
	values := strings.Split(encoded, ";")
	if len(values) != 3 {
		return &encrypted{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	if values[0] != MagicPrefix {
		return &encrypted{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	keyCiphertext, err := base64.StdEncoding.DecodeString(values[1])
	if err != nil {
		return &encrypted{}, errors.WrapPrefix(err, "Unable to base64 decode keyCiphertext", 0)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(values[2])
	if err != nil {
		return &encrypted{}, errors.WrapPrefix(err, "Unable to base64 decode ciphertext", 0)
	}

	return &encrypted{keyCiphertext: keyCiphertext, ciphertext: ciphertext}, nil
}
