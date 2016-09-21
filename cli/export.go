package cli

import (
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docExport = `
export: Export a secrets file in it's decrypted form.

Each secret in the file will be decrypted and output to standard out.
A number of formats are available:

  * bash:   export SECRET="password"
  * dotenv: SECRET="password"
  * json:   { "secret": "password" }

Please be careful when exporting your secrets, do not save them to disk!
`
const exampleExport = `
ejson-kms export
ejson-kms export --format=json
ejson-kms export --path=secrets.json --format=dotenv
`

func init() {
	App.AddCommand(exportCmd())
}

func exportCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "export",
		Short:   "export the decrypted secrets",
		Long:    strings.TrimSpace(docExport),
		Example: strings.TrimSpace(exampleExport),
	}

	var (
		storePath = ".secrets.json"
		format    = "bash"
	)

	cmd.Flags().StringVar(&storePath, "path", storePath, "path of the secrets file")
	cmd.Flags().StringVar(&format, "format", format, "format of the generated output (bash|dotenv|json)")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidCredentialsPath(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid path", 0)
		}

		store, err := model.Load(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to load JSON", 0)
		}

		formatter, err := utils.ValidFormatter(format)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid formatter", 0)
		}

		client, err := kms.NewClient()
		if err != nil {
			return errors.WrapPrefix(err, "Unable to initialize AWS client", 0)
		}

		items, err := store.ExportPlaintext(client)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to export items", 0)
		}

		err = formatter(os.Stdout, items)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to export items", 0)
		}

		return nil
	}

	return cmd

}
