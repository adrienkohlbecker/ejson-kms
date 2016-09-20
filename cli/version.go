package cli

import (
	"fmt"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"
)

var (
	Version string
	SHA1    string
	BuiltAt string
)

type versionCmd struct{}

func (cmd *versionCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "version",
		Short: "Prints the version of ejson-kms",
	}

	return c
}

func init() {
	addCommand(app, &versionCmd{})
}

func (cmd *versionCmd) Parse(args []string) errors.Error {
	return nil
}

func (cmd *versionCmd) Execute(args []string) errors.Error {
	fmt.Printf("ejson-kms %s (%s) built %s\n", Version, SHA1, BuiltAt)
	return nil
}
