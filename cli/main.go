package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

var (
	version string
	sha1    string
	builtAt string
)

const docApp = `
ejson-kms manages your secrets using Amazon KMS and a simple JSON file.
Complete documentation is available at https://github.com/adrienkohlbecker/ejson-kms
`

var App = &cobra.Command{
	Use:   "ejson-kms",
	Short: "ejson-kms manages your secrets using Amazon KMS and a simple JSON file",
	Long:  strings.TrimSpace(docApp),
}
