package cli

import (
	"fmt"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/crypto"
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docPrint = `
Print a credentials file in it's decrypted form.
`

type printCmd struct {
	credsPath string
	name      string

	creds *model.Store
}

func (cmd *printCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "print NAME",
		Short: "Print a credential in it's decrypted form.",
		Long:  strings.TrimSpace(docPrint),
	}

	c.Flags().StringVar(&cmd.credsPath, "path", ".credentials.json", "The path of the generated file.")

	return c
}

func init() {
	addCommand(app, &printCmd{})
}

func (cmd *printCmd) Parse(args []string) errors.Error {

	err := utils.ValidCredentialsPath(cmd.credsPath)
	if err != nil {
		return err
	}

	name, err := utils.HasOneArgument(args)
	if err != nil {
		return err
	}
	cmd.name = name

	err = utils.ValidName(cmd.name)
	if err != nil {
		return err
	}

	creds, err := model.Import(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to import JSON", 0)
	}
	cmd.creds = creds

	if !cmd.creds.Contains(cmd.name) {
		return errors.Errorf("The credential `%s` does not exist", cmd.name)
	}

	return nil
}

func (cmd *printCmd) Execute(args []string) errors.Error {

	client, err := kms.NewClient()
	if err != nil {
		return err
	}

	cipher := crypto.NewCipher(client, cmd.creds.KMSKeyID, cmd.creds.EncryptionContext)

	for _, item := range cmd.creds.Credentials {

		if item.Name == cmd.name {

			plaintext, loopErr := cipher.Decrypt(item.Ciphertext)
			if loopErr != nil {
				return errors.WrapPrefix(loopErr, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
			}

			fmt.Printf("%s", plaintext)

		}

	}

	return nil
}
