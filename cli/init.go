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

type initCmd struct {
	kmsKeyID             string
	credsPath            string
	rawEncryptionContext []string

	encryptionContext map[string]*string
}

func (cmd *initCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "init",
		Short: "Create a new credentials file",
		Long:  strings.TrimSpace(docInit),
	}

	c.Flags().StringVar(&cmd.kmsKeyID, "kms-key-id", "", "The KMS Key ID of your master encryption key for this file.")
	c.Flags().StringVar(&cmd.credsPath, "path", ".credentials.json", "The path of the generated file.")
	c.Flags().StringSliceVar(&cmd.rawEncryptionContext, "encryption-ontext", make([]string, 0), "Encryption context to add to the data keys, in the form \"KEY1=VALUE1,KEY2=VALUE2\".")

	return c
}

func init() {
	addCommand(app, &initCmd{})
}

func (cmd *initCmd) Parse(args []string) errors.Error {

	err := utils.ValidNewCredentialsPath(cmd.credsPath)
	if err != nil {
		return err
	}

	encryptionContext, err := utils.ValidEncryptionContext(cmd.rawEncryptionContext)
	if err != nil {
		return err
	}
	cmd.encryptionContext = encryptionContext

	if cmd.kmsKeyID == "" {
		return errors.Errorf("No KMS Key ID provided")
	}

	return nil
}

func (cmd *initCmd) Execute(args []string) errors.Error {

	store := model.NewStore(cmd.kmsKeyID, cmd.encryptionContext)

	err := store.Export(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to export JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}
