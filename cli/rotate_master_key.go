package cli

import (
	"fmt"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docRotateMasterKey = `
Rotate a credential from a credentials file.
`

func init() {
	App.AddCommand(rotateMasterKeyCmd())
}

func rotateMasterKeyCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "rotate-master-key NEW_KMS_KEY_ID",
		Short: "Rotate a master key from a credentials file.",
		Long:  strings.TrimSpace(docRotateMasterKey),
	}

	var storePath = ".credentials.json"
	cmd.Flags().StringVar(&storePath, "path", storePath, "The path of the generated file.")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidCredentialsPath(storePath)
		if err != nil {
			return err
		}

		newKMSKeyID, err := utils.HasOneArgument(args)
		if err != nil {
			return err
		}

		store, err := model.Load(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to load JSON", 0)
		}

		client, err := kms.NewClient()
		if err != nil {
			return err
		}

		err = store.RotateMasterKey(client, newKMSKeyID)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to rotate the master key", 0)
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
