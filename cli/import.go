package cli

import (
  "strings"

  "github.com/go-errors/errors"
  "github.com/spf13/cobra"
  "github.com/joho/godotenv"

  "github.com/adrienkohlbecker/ejson-kms/model"
  "github.com/adrienkohlbecker/ejson-kms/utils"
)

const docImport = `
import: Import values from a .env file and add them as secrets.

The .env file used should be in a key=value format. Key names can only contain letters,
digits and underscores. This is to ensure compatibility with the shell when using
the export command.
`

const exampleImport = `
ejson-kms import
ejson-kms import dev.env
ejson-kms import dev.env --path=secrets.json
`

func importCmd() *cobra.Command {

  cmd := &cobra.Command{
    Use:     "import",
    Short:   "import many secrets from a .env file",
    Long:    strings.TrimSpace(docImport),
    Example: strings.TrimSpace(exampleImport),
  }

  var (
    storePath = ".secrets.json"
    description = ""
  )

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

    store, err := model.Load(storePath)
    if err != nil {
      return errors.WrapPrefix(err, "Unable to load JSON", 0)
    }

    client, err := kmsDefaultClient()
    if err != nil {
      return errors.WrapPrefix(err, "Unable to initialize AWS client", 0)
    }

    importFile, err := godotenv.Read(name)
    if err != nil {
      return errors.WrapPrefix(err, "Unable to load import file", 0)
    }

    for k, v := range importFile {
      secretName := strings.ToLower(k)

      err = utils.ValidName(secretName)
      if err != nil {
        return errors.WrapPrefix(err, "Invalid name", 0)
      }

      if store.Contains(secretName) {
        cmd.Printf("Skipping %s: A secret with the same name already exists. Use the `rotate` command\n", secretName)
        continue
      }

      err = store.Add(client, v, secretName, description)
      if err != nil {
        return errors.WrapPrefix(err, "Unable to add secret", 0)
      }

      err = store.Save(storePath)
      if err != nil {
        return errors.WrapPrefix(err, "Unable to save JSON", 0)
      }
      cmd.Printf("Add secret: %s\n", secretName)
    }

    cmd.Printf("Exported new secrets in secrets file at: %s\n", storePath)
    return nil
  }

  return cmd

}
