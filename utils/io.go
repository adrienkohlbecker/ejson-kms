package utils

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/adrienkohlbecker/errors"
	"github.com/howeyc/gopass"
)

// ReadPassword reads the contents of the given file, and returns the contents
// with trimmed spaces
//
// If file is a terminal (such as when running with os.Stdin), it prints
// instructions to the user on how to close the input by sending an EOF.
func ReadPassword() (string, errors.Error) {

	isTTY := isTerminal(int(os.Stdin.Fd()))
	var bytes []byte
	var err error

	if isTTY {
		// Note: not covered by tests, need a way to test IsTerminal
		fmt.Println("Please enter the value and press enter:")
		bytes, err = gopass.GetPasswdMasked()
	} else {
		bytes, err = gopass.GetPasswd()
	}

	if err != nil {
		return "", errors.WrapPrefix(err, "Unable to read from stdin", 0)
	}

	value := strings.TrimSpace(string(bytes))
	return value, nil

}

// for mocking in tests
var isTerminal = terminal.IsTerminal
