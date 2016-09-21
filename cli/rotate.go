package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

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

	creds *model.Store
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

	creds, err := model.Load(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to load JSON", 0)
	}
	cmd.creds = creds

	if !cmd.creds.Contains(cmd.name) {
		return errors.Errorf("No credential with the given name has been found. Use the `add` command")
	}

	return nil
}

func (cmd *rotateCmd) Execute(args []string) errors.Error {

	plaintext, err := utils.ReadFromFile(os.Stdin)
	if err != nil {
		return err
	}

	client, err := kms.NewClient()
	if err != nil {
		return err
	}

	err = cmd.creds.Rotate(client, cmd.name, plaintext)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to rotate credential", 0)
	}

	err = cmd.creds.Save(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to save JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}
