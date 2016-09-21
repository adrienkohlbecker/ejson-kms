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

const docAdd = `
add: Add a secret to a secrets file.

The name of the secret must be in lowercase and can only contain letters,
digits and underscores. It cannot start with a digit. This is to ensure
compatibility with the shell when using the export command.

An optional, freeform, description can be provided. Use it to describe what the
item is for, how to rotate it, who is responsible and when...

It will ask you to type the secret at runtime, to avoid saving it to your
shell history. If you need to pass in the contents of a file (such as TLS keys),
you can pipe it's contents to stdin.
Please be mindful of your bash history when piping in strings.
`

const exampleAdd = `
ejson-kms add password
ejson-kms add password --path="secrets.json"
ejson-kms add password --description="Nuclear launch code"
cat tls-cert.key | ejson-kms add tls_key
`

func addCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "add NAME",
		Short:   "add a secret",
		Long:    strings.TrimSpace(docAdd),
		Example: strings.TrimSpace(exampleAdd),
	}

	var (
		storePath   = ".secrets.json"
		description = ""
	)

	cmd.Flags().StringVar(&storePath, "path", storePath, "path of the secrets file")
	cmd.Flags().StringVar(&description, "description", description, "freeform description of the secret")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidCredentialsPath(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid path", 0)
		}

		name, err := utils.HasOneArgument(args)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid name", 0)
		}

		err = utils.ValidName(name)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid name", 0)
		}

		store, err := model.Load(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to load JSON", 0)
		}

		if store.Contains(name) {
			return errors.Errorf("A secret with the same name already exists. Use the `rotate` command")
		}

		plaintext, err := utils.ReadFromFile(os.Stdin)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to read from stdin", 0)
		}

		client, err := kms.NewClient()
		if err != nil {
			return errors.WrapPrefix(err, "Unable to initalize AWS client", 0)
		}

		err = store.Add(client, plaintext, name, description)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to add secret", 0)
		}

		err = store.Save(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to save JSON", 0)
		}

		fmt.Printf("Exported new secrets file at: %s\n", storePath)
		return nil

	}

	return cmd

}
