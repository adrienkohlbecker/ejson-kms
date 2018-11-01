package formatter

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/go-errors/errors"
)

// JSON implements the Formatter interface.
//
// It outputs the decrypted secrets as JSON:
//
//  {
//    "my_secret": "my value",
//    "another_one": "string with \"quotes\""
//  }
func JSON(w io.Writer, creds <-chan Item) error {

	output := make(map[string]string)

	for item := range creds {
		output[item.Name] = item.Plaintext
	}

	b, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		// Note: Not covered in tests, need a way to trigger an encoding error.
		return errors.WrapPrefix(err, "Unable to format JSON", 0)
	}

	b = append(b, 0x0A) // add trailing new line

	_, err = io.Copy(w, bytes.NewReader(b))
	if err != nil {
		return errors.WrapPrefix(err, "Unable to write to output", 0)
	}

	return nil

}
