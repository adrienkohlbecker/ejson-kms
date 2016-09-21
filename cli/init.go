package cli

import (
	"fmt"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docInit = `
Create a new credentials file.
`

func init() {
	App.AddCommand(initCmd())
}

func initCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new credentials file",
		Long:  strings.TrimSpace(docInit),
	}

	var (
		kmsKeyID             = ""
		storePath            = ".credentials.json"
		rawEncryptionContext = make([]string, 0)
	)

	cmd.Flags().StringVar(&kmsKeyID, "kms-key-id", kmsKeyID, "The KMS Key ID of your master encryption key for this file.")
	cmd.Flags().StringVar(&storePath, "path", storePath, "The path of the generated file.")
	cmd.Flags().StringSliceVar(&rawEncryptionContext, "encryption-ontext", rawEncryptionContext, "Encryption context to add to the data keys, in the form \"KEY1=VALUE1,KEY2=VALUE2\".")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidNewCredentialsPath(storePath)
		if err != nil {
			return err
		}

		encryptionContext, err := utils.ValidEncryptionContext(rawEncryptionContext)
		if err != nil {
			return err
		}

		if kmsKeyID == "" {
			return errors.Errorf("No KMS Key ID provided")
		}

		store := model.NewStore(kmsKeyID, encryptionContext)

		err = store.Save(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to save JSON", 0)
		}

		fmt.Printf("Exported new credentials file at: %s\n", storePath)
		return nil

	}

	return cmd
}
