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

const docRotateMasterKey = `
Rotate a credential from a credentials file.
`

type rotateMasterKeyCmd struct {
	credsPath    string
	newKmsKeyARN string

	creds *model.JSON
}

func (cmd *rotateMasterKeyCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "rotate-master-key NEW_KMS_KEY_ARN",
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

	newKmsKeyARN, err := utils.HasOneArgument(args)
	if err != nil {
		return err
	}
	cmd.newKmsKeyARN = newKmsKeyARN

	creds, err := model.Import(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to import JSON", 0)
	}
	cmd.creds = creds

	return nil
}

func (cmd *rotateMasterKeyCmd) Execute(args []string) errors.Error {

	svc, err := kms.Service()
	if err != nil {
		return err
	}

	cipher := crypto.NewCipher(svc, cmd.creds.KMSKeyArn, cmd.creds.Context)
	newCipher := crypto.NewCipher(svc, cmd.newKmsKeyARN, cmd.creds.Context)

	for i, item := range cmd.creds.Credentials {

		fmt.Printf("KMS: Decrypting old plaintext for %s\n", item.Name)
		oldPlaintext, loopErr := cipher.Decrypt(item.Ciphertext)
		if loopErr != nil {
			return errors.WrapPrefix(loopErr, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
		}

		fmt.Printf("KMS: Encrypting new plaintext for %s\n", item.Name)
		ciphertext, loopErr := newCipher.Encrypt(oldPlaintext)
		if loopErr != nil {
			return errors.WrapPrefix(loopErr, "Unable to encrypt credential", 0)
		}

		item.Ciphertext = ciphertext
		cmd.creds.Credentials[i] = item

	}

	cmd.creds.KMSKeyArn = cmd.newKmsKeyARN

	err = cmd.creds.Export(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to export JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}
