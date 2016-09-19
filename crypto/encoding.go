package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/adrienkohlbecker/errors"
)

// MagicPrefix is a string prepended to all ciphertexts in the JSON representation.
// It will allow versioning the algorithm in the future.
const MagicPrefix = "EJK1]"

// Encrypted is a struct representation of a encrypted credential.
// It contains the ciphertext of both the credential and the data key.
type Encrypted struct {
	Ciphertext    []byte
	KeyCiphertext []byte
}

// Encode takes a raw message and encodes it for the JSON representation.
// The format is:
//
//   magicPrefix + ";" + base64(keyCiphertext) + ";" + base64(ciphertext)
func (encoded *Encrypted) Encode() string {
	return fmt.Sprintf("%s;%s;%s", MagicPrefix, base64.StdEncoding.EncodeToString(encoded.KeyCiphertext), base64.StdEncoding.EncodeToString(encoded.Ciphertext))
}

// Decode takes a string from the JSON representation and decodes the
// ciphertext and keyCiphertext, while validating the format.
func Decode(encoded string) (*Encrypted, errors.Error) {
	values := strings.Split(encoded, ";")
	if len(values) != 3 {
		return &Encrypted{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	if values[0] != MagicPrefix {
		return &Encrypted{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	keyCiphertext, err := base64.StdEncoding.DecodeString(values[1])
	if err != nil {
		return &Encrypted{}, errors.WrapPrefix(err, "Unable to base64 decode keyCiphertext", 0)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(values[2])
	if err != nil {
		return &Encrypted{}, errors.WrapPrefix(err, "Unable to base64 decode ciphertext", 0)
	}

	return &Encrypted{KeyCiphertext: keyCiphertext, Ciphertext: ciphertext}, nil
}
