package formatter

import (
	"io"
)

// Item is a parameter given to formatters, with the secret name
// and the associated plaintext
type Item struct {
	Name      string
	Plaintext string
}

// Formatter is the interface implemented by formatters.
//
// It takes any Writer and a channel of Items (to ease parallelization of KMS calls)
type Formatter func(w io.Writer, creds <-chan Item) error
