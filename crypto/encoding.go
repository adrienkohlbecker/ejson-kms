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

// Msg is a struct representation of a encrypted credential.
// It contains the ciphertext of both the credential and the data key.
type Msg struct {
	ciphertext    []byte
	keyCiphertext []byte
}

// Encode takes a raw message and encodes it for the JSON representation.
// The format is:
//
//   magicPrefix + ";" + base64(keyCiphertext) + ";" + base64(ciphertext)
func Encode(encoded Msg) string {
	return fmt.Sprintf("%s;%s;%s", MagicPrefix, base64.StdEncoding.EncodeToString(encoded.keyCiphertext), base64.StdEncoding.EncodeToString(encoded.ciphertext))
}

// Decode takes a string from the JSON representation and decodes the
// ciphertext and keyCiphertext, while validating the format.
func Decode(encoded string) (Msg, errors.Error) {
	values := strings.Split(encoded, ";")
	if len(values) != 3 {
		return Msg{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	if values[0] != MagicPrefix {
		return Msg{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	keyCiphertext, err := base64.StdEncoding.DecodeString(values[1])
	if err != nil {
		return Msg{}, errors.WrapPrefix(err, "Unable to base64 decode keyCiphertext", 0)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(values[2])
	if err != nil {
		return Msg{}, errors.WrapPrefix(err, "Unable to base64 decode ciphertext", 0)
	}

	return Msg{keyCiphertext: keyCiphertext, ciphertext: ciphertext}, nil
}
