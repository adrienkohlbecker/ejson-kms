package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

const docApp = `
ejson-kms manages your secrets using Amazon KMS and a simple JSON file.
Complete documentation is available at https://github.com/adrienkohlbecker/ejson-kms
`

var app = &cobra.Command{
	Use:   "ejson-kms",
	Short: "ejson-kms manages your secrets using Amazon KMS and a simple JSON file",
	Long:  strings.TrimSpace(docApp),
}
