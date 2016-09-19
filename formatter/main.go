package formatter

import (
	"io"

	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/errors"
)

// Item is a parameter given to formatters, with both the full credential data
// and the associated plaintext
type Item struct {
	Credential model.Credential
	Plaintext  string
}

// Formatter is the interface implemented by formatters.
//
// It takes any Writer and a channel of Items (to ease parallelization of KMS calls)
type Formatter func(w io.Writer, creds <-chan Item) errors.Error
