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

const docRotateKMSKey = `
rotate-kms-key: Rotates the KMS key used to encrypt a secrets file.

This command will decrypt all your secrets, and re-encrypt them using the
provided new KMS key.
The original file will be overwritten.
`

const exampleRotateKMSKey = `
ejson-kms rotate-kms-key arn:aws:kms:us-east-1:123456789012:alias/MyAliasName
`

func init() {
	App.AddCommand(rotateKMSKeyCmd())
}

func rotateKMSKeyCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "rotate-kms-key NEW_KMS_KEY_ID",
		Short:   "rotates the KMS key used to encrypt the secrets",
		Long:    strings.TrimSpace(docRotateKMSKey),
		Example: strings.TrimSpace(exampleRotateKMSKey),
	}

	var storePath = ".secrets.json"
	cmd.Flags().StringVar(&storePath, "path", storePath, "path of the secrets file")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidCredentialsPath(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid path", 0)
		}

		newKMSKeyID, err := utils.HasOneArgument(args)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid new KMS Key ID", 0)
		}

		store, err := model.Load(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to load JSON", 0)
		}

		client, err := kms.NewClient()
		if err != nil {
			return errors.WrapPrefix(err, "Unable to initialize AWS Client", 0)
		}

		err = store.RotateKMSKey(client, newKMSKeyID)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to rotate the KMS key", 0)
		}

		err = store.Save(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to save JSON", 0)
		}

		fmt.Printf("Exported new secrets file at: %s\n", storePath)
		return nil

	}

	return cmd
}
