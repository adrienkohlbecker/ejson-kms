package formatter

import (
	"encoding/json"
	"io"

	"github.com/adrienkohlbecker/errors"
)

func JSON(w io.Writer, creds <-chan Item) errors.Error {

	output := make(map[string]string)

	for item := range creds {
		output[item.Credential.Name] = item.Plaintext
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(output)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to format JSON", 0)
	}

	return nil

}
