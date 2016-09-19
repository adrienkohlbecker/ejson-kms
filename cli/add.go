package cli

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/adrienkohlbecker/errors"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/adrienkohlbecker/ejson-kms/crypto"
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/ejson-kms/model"
)

var nameRegexp = regexp.MustCompile("^[a-z_][a-z0-9_]*$")

const docAdd = `
Add a credential to a credentials file.
`

type addCmd struct {
	credsPath   string
	name        string
	description string
	value       string
	creds       *model.JSON
}

func (cmd *addCmd) Cobra() *cobra.Command {

	c := &cobra.Command{
		Use:   "add NAME",
		Short: "Add a credential to a credentials file.",
		Long:  strings.TrimSpace(docAdd),
	}

	c.Flags().StringVar(&cmd.credsPath, "path", ".credentials.json", "The path of the generated file.")
	c.Flags().StringVar(&cmd.description, "description", "", "Description of the credential.")

	return c
}

func init() {
	addCommand(app, &addCmd{})
}

func (cmd *addCmd) Parse(args []string) errors.Error {
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

	if cmd.creds.NameExists(cmd.name) {
		return errors.Errorf("A credential with the same name already exists. Use the `rotate` command")
	}

	return nil
}

func (cmd *addCmd) Execute(args []string) errors.Error {

	plaintext, err := readFromStdin()
	if err != nil {
		return errors.WrapPrefix(err, "Unable to read from Stdin", 0)
	}

	fmt.Printf("KMS: Encrypting plaintext for %s\n", cmd.name)

	svc, err := kms.Service()
	if err != nil {
		return errors.WrapPrefix(err, "Unable to open AWS session", 0)
	}

	ciphertext, err := crypto.Encrypt(svc, cmd.creds.KMSKeyArn, []byte(plaintext), cmd.creds.Context)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to encrypt credential", 0)
	}

	cred := model.Credential{
		Name:        cmd.name,
		Description: cmd.description,
		AddedAt:     time.Now().UTC().Truncate(time.Second),
		RotatedAt:   nil,
		Value:       ciphertext,
	}

	cmd.creds.Credentials = append(cmd.creds.Credentials, cred)

	err = cmd.creds.Export(cmd.credsPath)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to export JSON", 0)
	}

	fmt.Printf("Exported new credentials file at: %s\n", cmd.credsPath)

	return nil
}

func readFromStdin() (string, errors.Error) {

	if isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Println("Please enter the value and press Ctrl+D:")
	}

	reader := bufio.NewReader(os.Stdin)
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", errors.WrapPrefix(err, "Unable to read from stdin", 0)
	}

	value := strings.TrimSpace(string(bytes))
	return value, nil

}
