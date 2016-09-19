package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/crypto"
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
)

const docRotateMasterKey = `
Rotate a credential from a credentials file.
`

type rotateMasterKeyCmd struct {
	credsPath    string
	newKmsKeyARN string
	creds        *model.JSON
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
	if cmd.credsPath == "" {
		return errors.Errorf("No path provided")
	}

	stat, err := os.Stat(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, fmt.Sprintf("Unable to find credentials file at %s", cmd.credsPath), 0)
	}

	if stat.IsDir() {
		return errors.Errorf("Credentials file is a directory: %s", cmd.credsPath)
	}

	if len(args) == 1 {
		cmd.newKmsKeyARN = args[0]
	} else if len(args) > 0 {
		return errors.Errorf("More than one new key ARN provided")
	} else {
		return errors.Errorf("No new key ARN provided")
	}

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
		return errors.WrapPrefix(err, "Unable to open AWS session", 0)
	}

	for i, item := range cmd.creds.Credentials {

		fmt.Printf("KMS: Decrypting old plaintext for %s\n", item.Name)
		oldPlaintext, loopErr := crypto.Decrypt(svc, item.Value, cmd.creds.Context)
		if loopErr != nil {
			return errors.WrapPrefix(loopErr, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
		}

		fmt.Printf("KMS: Encrypting new plaintext for %s\n", item.Name)
		ciphertext, loopErr := crypto.Encrypt(svc, cmd.newKmsKeyARN, []byte(oldPlaintext), cmd.creds.Context)
		if loopErr != nil {
			return errors.WrapPrefix(loopErr, "Unable to encrypt credential", 0)
		}

		item.Value = ciphertext
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
