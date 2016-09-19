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
)

const docExport = `
Export a credentials file in it's decrypted form.
`

type exportCmd struct {
	credsPath string
	creds     *model.JSON
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

	creds, err := model.Import(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to import JSON", 0)
	}
	cmd.creds = creds

	switch cmd.format {
	case "bash":
		cmd.formatter = formatter.Bash
	case "dotenv":
		cmd.formatter = formatter.Dotenv
	case "json":
		cmd.formatter = formatter.JSON
	default:
		return errors.Errorf("Unknown format %s", cmd.format)
	}

	return nil
}

func (cmd *exportCmd) Execute(args []string) errors.Error {

	svc, err := kms.Service()
	if err != nil {
		return errors.WrapPrefix(err, "Unable to open AWS session", 0)
	}

	items := make(chan formatter.Item, len(cmd.creds.Credentials))

	for _, item := range cmd.creds.Credentials {

		plaintext, loopErr := crypto.Decrypt(svc, item.Value, cmd.creds.Context)
		if loopErr != nil {
			return errors.WrapPrefix(loopErr, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
		}

		items <- formatter.Item{Credential: item, Plaintext: string(plaintext)}

	}

	close(items)

	err = cmd.formatter(os.Stdout, items)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to export items", 0)
	}

	return nil
}
