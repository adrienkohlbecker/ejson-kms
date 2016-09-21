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

const docRotate = `
Rotate a credential from a credentials file.
`

func init() {
	App.AddCommand(rotateCmd())
}

func rotateCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "rotate NAME",
		Short: "Rotate a credential from a credentials file.",
		Long:  strings.TrimSpace(docRotate),
	}

	var storePath = ".credentials.json"
	cmd.Flags().StringVar(&storePath, "path", storePath, "The path of the generated file.")

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

		if !store.Contains(name) {
			return errors.Errorf("No credential with the given name has been found. Use the `add` command")
		}

		plaintext, err := utils.ReadFromFile(os.Stdin)
		if err != nil {
			return err
		}

		client, err := kms.NewClient()
		if err != nil {
			return err
		}

		err = store.Rotate(client, name, plaintext)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to rotate credential", 0)
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
