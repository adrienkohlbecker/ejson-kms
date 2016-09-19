package cli

import (
	"fmt"
	"os"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"
)

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
