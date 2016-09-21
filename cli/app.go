package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

const docApp = `
ejson-kms manages your secrets using Amazon KMS and a simple JSON file.
Complete documentation is available at https://github.com/adrienkohlbecker/ejson-kms
`

// App is the main ejson-kms command.
func App() *cobra.Command {

	var cmd = &cobra.Command{
		Use:               "ejson-kms",
		Short:             "ejson-kms manages your secrets using Amazon KMS and a simple JSON file",
		Long:              strings.TrimSpace(docApp),
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(addCmd())
	cmd.AddCommand(exportCmd())
	cmd.AddCommand(initCmd())
	cmd.AddCommand(rotateKMSKeyCmd())
	cmd.AddCommand(rotateCmd())
	cmd.AddCommand(versionCmd())

	return cmd

}
