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

const docPrint = `
Print a credentials file in it's decrypted form.
`

type printCmd struct {
	credsPath string
	creds     *model.JSON
	name      string
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
		cmd.name = args[0]
	} else if len(args) > 0 {
		return errors.Errorf("More than one name provided")
	} else {
		return errors.Errorf("No name provided")
	}

	if !nameRegexp.MatchString(cmd.name) {
		return errors.Errorf("Invalid format for name: must be lowercase, can contain letters, digits and underscores, and cannot start with a number.")
	}

	creds, err := model.Import(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to import JSON", 0)
	}
	cmd.creds = creds

	if !cmd.creds.NameExists(cmd.name) {
		return errors.Errorf("The credential `%s` does not exist", cmd.name)
	}

	return nil
}

func (cmd *printCmd) Execute(args []string) errors.Error {

	svc, err := kms.Service()
	if err != nil {
		return errors.WrapPrefix(err, "Unable to open AWS session", 0)
	}

	for _, item := range cmd.creds.Credentials {

		if item.Name == cmd.name {

			plaintext, loopErr := crypto.Decrypt(svc, item.Value, cmd.creds.Context)
			if loopErr != nil {
				return errors.WrapPrefix(loopErr, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
			}

			fmt.Printf("%s", plaintext)

		}

	}

	return nil
}
