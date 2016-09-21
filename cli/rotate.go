package cli

import (
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/adrienkohlbecker/ejson-kms/utils"
)

const docRotate = `
rotate: Rotate a secret from a secrets file.

This will decrypt the given secret, check that the values are indeed different,
and store the new encrypted value.

It will ask you to type the secret at runtime, to avoid saving it to your
shell history. If you need to pass in the contents of a file (such as TLS keys),
you can pipe it's contents to stdin.
Please be mindful of your bash history when piping in strings.
`

const exampleRotate = `
ejson-kms rotate password
cat tls-cert.key | ejson-kms rotate tls_key
`

func rotateCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "rotate NAME",
		Short:   "rotate a secret",
		Long:    strings.TrimSpace(docRotate),
		Example: strings.TrimSpace(exampleRotate),
	}

	var storePath = ".secrets.json"
	cmd.Flags().StringVar(&storePath, "path", storePath, "path of the secrets file")

	cmd.RunE = func(_ *cobra.Command, args []string) error {

		err := utils.ValidSecretsPath(storePath)
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

		if !store.Contains(name) {
			return errors.Errorf("No secret with the given name has been found. Use the `add` command")
		}

		plaintext, err := utils.ReadFromFile(os.Stdin)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to read from stdin", 0)
		}

		client, err := kmsNewClient()
		if err != nil {
			return errors.WrapPrefix(err, "Unable to initialize AWS client", 0)
		}

		err = store.Rotate(client, name, plaintext)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to rotate secret", 0)
		}

		err = store.Save(storePath)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to save JSON", 0)
		}

		cmd.Printf("Exported new secrets file at: %s\n", storePath)
		return nil
	}

	return cmd
}
