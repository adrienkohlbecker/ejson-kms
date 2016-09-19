package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/crypto"
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docRotate = `
Rotate a credential from a credentials file.
`

type rotateCmd struct {
	credsPath string
	name      string

	creds *model.JSON
}

func (cmd *rotateCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "rotate NAME",
		Short: "Rotate a credential from a credentials file.",
		Long:  strings.TrimSpace(docRotate),
	}

	c.Flags().StringVar(&cmd.credsPath, "path", ".credentials.json", "The path of the generated file.")

	return c
}

func init() {
	addCommand(app, &rotateCmd{})
}

func (cmd *rotateCmd) Parse(args []string) errors.Error {

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

	if !cmd.creds.NameExists(cmd.name) {
		return errors.Errorf("No credential with the given name has been found. Use the `add` command")
	}

	return nil
}

func (cmd *rotateCmd) Execute(args []string) errors.Error {

	plaintext, err := utils.ReadFromStdin()
	if err != nil {
		return err
	}

	svc, err := kms.Service()
	if err != nil {
		return err
	}

	for i, item := range cmd.creds.Credentials {

		if item.Name == cmd.name {

			fmt.Printf("KMS: Decrypting old plaintext for %s\n", cmd.name)
			oldPlaintext, loopErr := crypto.Decrypt(svc, item.Value, cmd.creds.Context)
			if loopErr != nil {
				return errors.WrapPrefix(loopErr, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
			}

			if string(oldPlaintext) == plaintext {
				return errors.Errorf("Trying to rotate a credential and giving the same value")
			}

			fmt.Printf("KMS: Encrypting new plaintext for %s\n", cmd.name)
			now := time.Now().UTC().Truncate(time.Second)
			ciphertext, loopErr := crypto.Encrypt(svc, cmd.creds.KMSKeyArn, []byte(plaintext), cmd.creds.Context)
			if loopErr != nil {
				return errors.WrapPrefix(loopErr, "Unable to encrypt credential", 0)
			}

			item.Value = ciphertext
			item.RotatedAt = &now
			cmd.creds.Credentials[i] = item

			break
		}

	}

	err = cmd.creds.Export(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to export JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}
