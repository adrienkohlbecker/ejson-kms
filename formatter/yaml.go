package formatter

import (
	"bytes"
	"io"

	"github.com/go-errors/errors"
	"gopkg.in/yaml.v2"
)

// YAML implements the Formatter interface.
//
// It outputs the decrypted secrets as YAML:
//
//  my_secret: my value
//  another_one: string with "quotes"
func YAML(w io.Writer, creds <-chan Item) error {

	output := make(map[string]string)

	for item := range creds {
		output[item.Name] = item.Plaintext
	}
	b, err := yaml.Marshal(output)
	if err != nil {
		// Note: Not covered in tests, need a way to trigger an encoding error.
		return errors.WrapPrefix(err, "Unable to format YAML", 0)
	}

	_, err = io.Copy(w, bytes.NewReader(b))
	if err != nil {
		return errors.WrapPrefix(err, "Unable to write to output", 0)
	}

	return nil

}
