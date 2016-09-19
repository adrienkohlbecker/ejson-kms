package formatter

import (
	"io"

	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/errors"
)

type Item struct {
	Credential model.Credential
	Plaintext  string
}

type Formatter func(w io.Writer, creds <-chan Item) errors.Error
