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

	cipher := crypto.NewCipher(client, cmd.creds.KMSKeyID, cmd.creds.EncryptionContext)
	newCipher := crypto.NewCipher(client, cmd.newKMSKeyID, cmd.creds.EncryptionContext)

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

	cmd.creds.KMSKeyID = cmd.newKMSKeyID

	err = cmd.creds.Save(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to save JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}
