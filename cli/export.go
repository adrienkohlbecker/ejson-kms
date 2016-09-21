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
Export a credentials file in it's decrypted form.
`

func init() {
	App.AddCommand(exportCmd())
}

func exportCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a credentials file in it's decrypted form.",
		Long:  strings.TrimSpace(docExport),
	}

	var (
		storePath = ".credentials.json"
		format    = "bash"
	)

	cmd.Flags().StringVar(&storePath, "path", storePath, "The path of the generated file.")
	cmd.Flags().StringVar(&format, "format", format, "The format of the generated output (bash|dotenv|json)")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidCredentialsPath(storePath)
		if err != nil {
			return err
		}

		store, err := model.Load(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to load JSON", 0)
		}

		formatter, err := utils.ValidFormatter(format)
		if err != nil {
			return err
		}

		client, err := kms.NewClient()
		if err != nil {
			return err
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
