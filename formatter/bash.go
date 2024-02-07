package formatter

import (
	"fmt"
	"io"
	"strings"
)

// Bash implements the Formatter interface.
//
// It outputs the decrypted secrets in the form:
//
//   MY_SECRET='my value'
//   ANOTHER_ONE='string with ''quotes'''
//
// The secret names are capitalized and the no processing is done to the string
// except replacing all `'` with `''`.
func Bash(w io.Writer, creds <-chan Item) error {

	for item := range creds {
		key := strings.ToUpper(item.Name)
		value := item.Plaintext
		value = strings.Replace(value, "'", "''", -1)
		_, err := fmt.Fprintf(w, "%s='%s'\n", key, value)
		if err != nil {
			return err
		}
	}

	return nil

}

// BashIfNotSet implements the Formatter interface.
//
// It outputs the decrypted secrets in the form:
//
//   : ${MY_SECRET='my value'}
//   : ${ANOTHER_ONE='string with ''quotes'''}
//
// The secret names are capitalized and the no processing is done to the string
// except replacing all `'` with `''`.
//
// This will set the environment variable
// only if it has not been previously set.
func BashIfNotSet(w io.Writer, creds <-chan Item) error {

	for item := range creds {
		key := strings.ToUpper(item.Name)
		value := item.Plaintext
		value = strings.Replace(value, "'", "''", -1)
		_, err := fmt.Fprintf(w, ": ${%s='%s'}\n", key, value)
		if err != nil {
			return err
		}
	}

	return nil

}

// BashIfEmpty implements the Formatter interface.
//
// It outputs the decrypted secrets in the form:
//
//   : ${MY_SECRET:='my value'}
//   : ${ANOTHER_ONE:='string with ''quotes'''}
//
// The secret names are capitalized and the no processing is done to the string
// except replacing all `'` with `''`.
//
// This will set the environment variable
// only if it has not been previously set or if it is an empty string.
func BashIfEmpty(w io.Writer, creds <-chan Item) error {

	for item := range creds {
		key := strings.ToUpper(item.Name)
		value := item.Plaintext
		value = strings.Replace(value, "'", "''", -1)
		_, err := fmt.Fprintf(w, ": ${%s:='%s'}\n", key, value)
		if err != nil {
			return err
		}
	}

	return nil

}
