package utils

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
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

// Fatal prints a pretty error message when a cobra command returns an error.
//
// Included in the output is the error message and a prompt to check out the
// documentation.
//
// If the environment variable EJSON_KMS_DEBUG is set to 1, it also prints
// the stacktrace of the given error.
func Fatal(cmd *cobra.Command, err errors.Error) {

	fmt.Fprintf(os.Stderr, "%s\n", err)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Run `%s --help` for documentation\n", cmd.CommandPath())

	enableDebug := os.Getenv("EJSON_KMS_DEBUG") == "1"
	if enableDebug {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintln(os.Stderr, string(err.Stack()))
	}

}
