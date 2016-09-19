package formatter

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/adrienkohlbecker/errors"
)

func Dotenv(w io.Writer, creds <-chan Item) errors.Error {

	for item := range creds {
		fmt.Fprintf(w, "%s=%s\n", strings.ToUpper(item.Credential.Name), strconv.QuoteToASCII(item.Plaintext))
	}

	return nil

}
