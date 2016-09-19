package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/adrienkohlbecker/errors"
)

const magicPrefix = "EJK1]"

type msg struct {
	ciphertext    []byte
	keyCiphertext []byte
}

func encode(encoded msg) string {
	return fmt.Sprintf("%s;%s;%s", magicPrefix, base64.StdEncoding.EncodeToString(encoded.keyCiphertext), base64.StdEncoding.EncodeToString(encoded.ciphertext))
}

func decode(encoded string) (msg, errors.Error) {
	values := strings.SplitN(encoded, ";", 3)
	if len(values) != 3 {
		return msg{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	if values[0] != magicPrefix {
		return msg{}, errors.Errorf("Invalid format for encoded string %s", encoded)
	}

	keyCiphertext, err := base64.StdEncoding.DecodeString(values[1])
	if err != nil {
		return msg{}, errors.WrapPrefix(err, "Unable to base64 decode keyCiphertext", 0)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(values[1])
	if err != nil {
		return msg{}, errors.WrapPrefix(err, "Unable to base64 decode ciphertext", 0)
	}

	return msg{keyCiphertext: keyCiphertext, ciphertext: ciphertext}, nil
}
