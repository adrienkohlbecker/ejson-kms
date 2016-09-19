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

func ReadFromStdin() (string, errors.Error) {

	if isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Println("Please enter the value and press Ctrl+D:")
	}

	reader := bufio.NewReader(os.Stdin)
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", errors.WrapPrefix(err, "Unable to read from stdin", 0)
	}

	value := strings.TrimSpace(string(bytes))
	return value, nil

}

func Fatal(cmd *cobra.Command, err errors.Error, msg string) {

	fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Run `%s --help` for documentation\n", cmd.CommandPath())

	enableDebug := os.Getenv("EJSON_KMS_DEBUG") == "1"
	if enableDebug {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintln(os.Stderr, string(err.Stack()))
	}

	os.Exit(1)

}
