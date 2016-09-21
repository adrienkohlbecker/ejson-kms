package utils

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/mattn/go-isatty"
)

// ReadFromFile reads the contents of the given file, and returns the contents
// with trimmed spaces
//
// If file is a terminal (such as when running with os.Stdin), it prints
// instructions to the user on how to close the input by sending an EOF.
func ReadFromFile(file *os.File) (string, errors.Error) {

	if isatty.IsTerminal(file.Fd()) {
		// Note: not covered by tests, need a way to test IsTerminal
		fmt.Println("Please enter the value and press Enter then Ctrl+D:")
	}

	reader := bufio.NewReader(file)
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", errors.WrapPrefix(err, "Unable to read from file", 0)
	}

	value := strings.TrimSpace(string(bytes))
	return value, nil

}
