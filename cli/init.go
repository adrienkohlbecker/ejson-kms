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
init: Create a new secrets file.

You must provide an AWS KMS key ID, which can take multiple forms (see examples).

Optionaly, you can add en encryption context to the generated file, in the form
of key-value pairs. Note that the only way to modify this context afterwards is
via the "edit-context" command.
Manually editing it in the JSON file will render the file un-decipherable.

If a file exists at the destination, the command will exit. You can change the
default destination path (.secrets.json) with the "--path" flag.
`

const exampleInit = `
ejson-kms init --kms-key-id="arn:aws:kms:us-east-1:123456789012:alias/MyAliasName"
ejson-kms init --kms-key-id="alias/MyAliasName" --encryption-context="KEY1=VALUE1,KEY2=VALUE2"
ejson-kms init --kms-key-id="12345678-1234-1234-1234-123456789012" --path="secrets.json"
`

func init() {
	App.AddCommand(initCmd())
}

func initCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "init --kms-key-id=KMS_KEY_ID",
		Short:   "create a new secrets file",
		Long:    strings.TrimSpace(docInit),
		Example: strings.TrimSpace(exampleInit),
	}

	var (
		kmsKeyID             = ""
		storePath            = ".secrets.json"
		rawEncryptionContext = make([]string, 0)
	)

	cmd.Flags().StringVar(&kmsKeyID, "kms-key-id", kmsKeyID, "KMS Key ID of your master encryption key for this file")
	cmd.Flags().StringVar(&storePath, "path", storePath, "path of the generated file")
	cmd.Flags().StringSliceVar(&rawEncryptionContext, "encryption-context", rawEncryptionContext, "encryption context added to the data keys (\"KEY1=VALUE1,KEY2=VALUE2\")")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidNewCredentialsPath(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid path", 0)
		}

		encryptionContext, err := utils.ValidEncryptionContext(rawEncryptionContext)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid encryption context", 0)
		}

		if kmsKeyID == "" {
			return errors.Errorf("No KMS Key ID provided")
		}

		store := model.NewStore(kmsKeyID, encryptionContext)

		err = store.Save(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to save JSON", 0)
		}

		fmt.Printf("Exported new secrets file at: %s\n", storePath)
		return nil

	}

	return cmd
}
