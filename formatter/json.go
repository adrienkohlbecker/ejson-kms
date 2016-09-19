package formatter

import (
	"encoding/json"
	"io"

	"github.com/adrienkohlbecker/errors"
)

// JSON implements the Formatter interface.
//
// It outputs the credentials as JSON:
//
//  {
//    "my_credential": "my value",
//    "another_one": "string with \"quotes\""
//  }
func JSON(w io.Writer, creds <-chan Item) errors.Error {

	output := make(map[string]string)

	for item := range creds {
		output[item.Credential.Name] = item.Plaintext
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(output)
	if err != nil {
		// Note: Not covered in tests, need a way to trigger an encoding error.
		return errors.WrapPrefix(err, "Unable to format JSON", 0)
	}

	return nil

}
