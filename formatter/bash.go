package formatter

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/adrienkohlbecker/errors"
)

func Bash(w io.Writer, creds <-chan Item) errors.Error {

	for item := range creds {
		fmt.Fprintf(w, "export %s=%s\n", strings.ToUpper(item.Credential.Name), strconv.QuoteToASCII(item.Plaintext))
	}

	return nil

}
