package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/adrienkohlbecker/errors"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/model"
)

const docInit = `
Create a new credentials file.
`

type initCmd struct {
	kmsKeyARN  string
	credsPath  string
	rawContext []string
	context    map[string]string
}

func (cmd *initCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "init",
		Short: "Create a new credentials file",
		Long:  strings.TrimSpace(docInit),
	}

	c.Flags().StringVar(&cmd.kmsKeyARN, "kms-key-arn", "", "The KMS Key ARN of your master encryption key for this file.")
	c.Flags().StringVar(&cmd.credsPath, "path", ".credentials.json", "The path of the generated file.")
	c.Flags().StringSliceVar(&cmd.rawContext, "context", make([]string, 0), "Context to add to the data keys, in the form \"KEY1=VALUE1,KEY2=VALUE2\".")

	return c
}

func init() {
	addCommand(app, &initCmd{})
}

func (cmd *initCmd) Parse(args []string) errors.Error {
	if cmd.credsPath == "" {
		return errors.Errorf("No path provided")
	}

	_, err := os.Stat(cmd.credsPath)
	if err == nil {
		return errors.Errorf(fmt.Sprintf("A file already exists at %s", cmd.credsPath), 0)
	}

	if cmd.kmsKeyARN == "" {
		return errors.Errorf("No KMS Key ARN provided")
	}

	cmd.context = make(map[string]string)
	for _, item := range cmd.rawContext {
		splitted := strings.SplitN(item, "=", 2)
		if len(splitted) != 2 {
			return errors.Errorf("Invalid format for context")
		}
		cmd.context[splitted[0]] = splitted[1]
	}

	return nil
}

func (cmd *initCmd) Execute(args []string) errors.Error {

	j := &model.JSON{}
	j.KMSKeyArn = cmd.kmsKeyARN
	j.Context = cmd.context
	j.Credentials = make([]model.Credential, 0)

	err := j.Export(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to export JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}
