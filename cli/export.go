package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/crypto"
	"github.com/adrienkohlbecker/ejson-kms/formatter"
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docExport = `
Export a credentials file in it's decrypted form.
`

type exportCmd struct {
	credsPath string
	creds     *model.Store
	format    string
	formatter formatter.Formatter
}

func (cmd *exportCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "export",
		Short: "Export a credentials file in it's decrypted form.",
		Long:  strings.TrimSpace(docExport),
	}

	c.Flags().StringVar(&cmd.credsPath, "path", ".credentials.json", "The path of the generated file.")
	c.Flags().StringVar(&cmd.format, "format", "bash", "The format of the generated output (bash|dotenv|json)")

	return c
}

func init() {
	addCommand(app, &exportCmd{})
}

func (cmd *exportCmd) Parse(args []string) errors.Error {

	err := utils.ValidCredentialsPath(cmd.credsPath)
	if err != nil {
		return err
	}

	creds, err := model.Import(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to import JSON", 0)
	}
	cmd.creds = creds

	formatter, err := utils.ValidFormatter(cmd.format)
	if err != nil {
		return err
	}
	cmd.formatter = formatter

	return nil
}

func (cmd *exportCmd) Execute(args []string) errors.Error {

	client, err := kms.NewClient()
	if err != nil {
		return err
	}

	items := make(chan formatter.Item, len(cmd.creds.Credentials))
	cipher := crypto.NewCipher(client, cmd.creds.KMSKeyID, cmd.creds.EncryptionContext)

	for _, item := range cmd.creds.Credentials {

		plaintext, loopErr := cipher.Decrypt(item.Ciphertext)
		if loopErr != nil {
			return errors.WrapPrefix(loopErr, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
		}

		items <- formatter.Item{Credential: item, Plaintext: plaintext}

	}

	close(items)

	err = cmd.formatter(os.Stdout, items)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to export items", 0)
	}

	return nil
}
