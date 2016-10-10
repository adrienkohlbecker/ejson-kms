package formatter

import (
	"fmt"
	"io"
	"strings"

	"github.com/adrienkohlbecker/errors"
)

// Bash implements the Formatter interface.
//
// It outputs the decrypted secrets in the form:
//
//   export MY_SECRET='my value'
//   export ANOTHER_ONE='string with ''quotes'''
//
// The secret names are capitalized and the no processing is done to the string
// except replacing all `'` with `''`.
func Bash(w io.Writer, creds <-chan Item) errors.Error {

	for item := range creds {
		key := strings.ToUpper(item.Name)
		value := item.Plaintext
		value = strings.Replace(value, "'", "''", -1)
		fmt.Fprintf(w, "export %s='%s'\n", key, value)
	}

	return nil

}
