package cli

import (
	"github.com/adrienkohlbecker/ejson-kms/utils"
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
			utils.Fatal(cobraCmd, err, "The provided arguments are invalid")
		}

		err = cmd.Execute(args)
		if err != nil {
			utils.Fatal(cobraCmd, err, "Unable to execute command")
		}

	}

	app.AddCommand(cobraCmd)

}
