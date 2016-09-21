package formatter

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/adrienkohlbecker/errors"
)

// Bash implements the Formatter interface.
//
// It outputs the credentials in the form:
//
//   export MY_CREDENTIAL="my value"
//   export ANOTHER_ONE="string with \"quotes\""
//
// The credential names are capitalized and the values are quoted as Go strings.
//
// TODO: Ensure the go syntax for strings is compatible with Bash, as it seems
// to be the case from quick testing.
func Bash(w io.Writer, creds <-chan Item) errors.Error {

	for item := range creds {
		key := strings.ToUpper(item.Name)
		value := strconv.QuoteToASCII(item.Plaintext)
		fmt.Fprintf(w, "export %s=%s\n", key, value)
	}

	return nil

}
