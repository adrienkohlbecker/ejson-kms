package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docAdd = `
Add a credential to a credentials file.
`

func init() {
	App.AddCommand(addCmd())
}

func addCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "add NAME",
		Short: "Add a credential to a credentials file.",
		Long:  strings.TrimSpace(docAdd),
	}

	var (
		storePath   = ".credentials.json"
		description = ""
	)

	cmd.Flags().StringVar(&storePath, "path", storePath, "The path of the generated file.")
	cmd.Flags().StringVar(&description, "description", description, "Description of the credential.")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidCredentialsPath(storePath)
		if err != nil {
			return err
		}

		name, err := utils.HasOneArgument(args)
		if err != nil {
			return err
		}

		err = utils.ValidName(name)
		if err != nil {
			return err
		}

		store, err := model.Load(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to load JSON", 0)
		}

		if store.Contains(name) {
			return errors.Errorf("A credential with the same name already exists. Use the `rotate` command")
		}

		plaintext, err := utils.ReadFromFile(os.Stdin)
		if err != nil {
			return err
		}

		client, err := kms.NewClient()
		if err != nil {
			return err
		}

		err = store.Add(client, plaintext, name, description)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to add credential", 0)
		}

		err = store.Save(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to save JSON", 0)
		}

		fmt.Printf("Exported new credentials file at: %s\n", storePath)

		return nil

	}

	return cmd

}
