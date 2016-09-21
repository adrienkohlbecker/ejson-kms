package formatter

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/adrienkohlbecker/errors"
)

// Dotenv implements the Formatter interface.
//
// It outputs the decrypted secrets in the form:
//
//   MY_CREDENTIAL="my value"
//   ANOTHER_ONE="string with \"quotes\""
//
// The secret names are capitalized and the values are quoted as Go strings.
//
// TODO: Ensure the go syntax for strings is compatible with Dotenv, as it seems
// to be the case from quick testing.
func Dotenv(w io.Writer, creds <-chan Item) errors.Error {

	for item := range creds {
		key := strings.ToUpper(item.Name)
		value := strconv.QuoteToASCII(item.Plaintext)
		fmt.Fprintf(w, "%s=%s\n", key, value)
	}

	return nil

}
