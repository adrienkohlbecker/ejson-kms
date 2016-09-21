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

type rotateMasterKeyCmd struct {
	credsPath   string
	newKMSKeyID string

	creds *model.Store
}

func (cmd *rotateMasterKeyCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "rotate-master-key NEW_KMS_KEY_ID",
		Short: "Rotate a master key from a credentials file.",
		Long:  strings.TrimSpace(docRotateMasterKey),
	}

	c.Flags().StringVar(&cmd.credsPath, "path", ".credentials.json", "The path of the generated file.")

	return c
}

func init() {
	addCommand(app, &rotateMasterKeyCmd{})
}

func (cmd *rotateMasterKeyCmd) Parse(args []string) errors.Error {

	err := utils.ValidCredentialsPath(cmd.credsPath)
	if err != nil {
		return err
	}

	newKMSKeyID, err := utils.HasOneArgument(args)
	if err != nil {
		return err
	}
	cmd.newKMSKeyID = newKMSKeyID

	creds, err := model.Load(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to load JSON", 0)
	}
	cmd.creds = creds

	return nil
}

func (cmd *rotateMasterKeyCmd) Execute(args []string) errors.Error {

	client, err := kms.NewClient()
	if err != nil {
		return err
	}

	err = cmd.creds.RotateMasterKey(client, cmd.newKMSKeyID)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to rotate the master key", 0)
	}

	err = cmd.creds.Save(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to save JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}
