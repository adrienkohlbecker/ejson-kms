package cli

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var nameRegexp = regexp.MustCompile("^[a-z_][a-z0-9_]*$")

type command interface {
	Cobra() *cobra.Command
	Parse(args []string) errors.Error
	Execute(args []string) errors.Error
}

func Execute() error {
	return app.Execute()
}

func addCommand(app *cobra.Command, cmd command) {

	cobraCmd := cmd.Cobra()
	cobraCmd.Run = func(thisCmd *cobra.Command, args []string) {

		err := cmd.Parse(args)
		if err != nil {
			fatal(cobraCmd, err, "The provided arguments are invalid")
		}

		err = cmd.Execute(args)
		if err != nil {
			fatal(cobraCmd, err, "Unable to execute command")
		}

	}

	app.AddCommand(cobraCmd)

}

func fatal(cmd *cobra.Command, err errors.Error, msg string) {

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

func readFromStdin() (string, errors.Error) {

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
