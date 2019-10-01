package utils

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/adrienkohlbecker/ejson-kms/formatter"
	"github.com/go-errors/errors"
)

var nameRegexp = regexp.MustCompile("^[a-z_][a-z0-9_]*$")

// ValidSecretsPath checks for an existing path that is not a directory.
func ValidSecretsPath(path string) error {

	if path == "" {
		return errors.Errorf("No path provided")
	}

	stat, err := os.Stat(path)
	if err != nil {
		return errors.WrapPrefix(err, fmt.Sprintf("Unable to find secrets file at %s", path), 0)
	}

	if stat.IsDir() {
		return errors.Errorf("Secrets file is a directory: %s", path)
	}

	return nil

}

// ValidNewSecretsPath checks for a valid path that does not exist.
func ValidNewSecretsPath(path string) error {

	if path == "" {
		return errors.Errorf("No path provided")
	}

	_, err := os.Stat(path)
	if err == nil {
		return errors.Errorf("A file already exists at %s", path)
	}

	return nil

}

// ValidName checks if the provided string is valid as a secret name.
//
// It must be only lowercase letters, digits or underscores.
// It cannot start with a letter.
func ValidName(name string) error {

	if !nameRegexp.MatchString(name) {
		return errors.Errorf("Invalid format for name: must be lowercase, can contain letters, digits and underscores, and cannot start with a number.")
	}

	return nil
}

// HasOneArgument checks that the provided string slice has one (and only one)
// value that is not empty, and returns it.
func HasOneArgument(args []string) (string, error) {

	var value string
	if len(args) == 1 {
		value = args[0]
	} else if len(args) > 0 {
		return "", errors.Errorf("More than one argument provided")
	} else {
		return "", errors.Errorf("No argument provided")
	}

	if value == "" {
		return "", errors.Errorf("Empty argument")
	}

	return value, nil
}

// ValidEncryptionContext parses the CLI form of key-value pairs used for
// encryption contexts.
// The format must be key1=value1. Keys and values are not checked for
// a specific format
func ValidEncryptionContext(raw []string) (map[string]*string, error) {

	encryptionContext := make(map[string]*string)

	for _, item := range raw {
		splitted := strings.Split(item, "=")
		if len(splitted) != 2 {
			return encryptionContext, errors.Errorf("Invalid format for encryption context")
		}
		encryptionContext[splitted[0]] = &splitted[1]
	}

	return encryptionContext, nil
}

// ValidFormatter parses the formatter string argument into a formatter
// method. Supported values are "bash", "dotenv", "json" and "yaml".
func ValidFormatter(format string) (formatter.Formatter, error) {

	var ret formatter.Formatter

	switch format {
	case "bash":
		ret = formatter.Bash
	case "bash-export":
		ret = formatter.BashExport
	case "dotenv":
		ret = formatter.Dotenv
	case "json":
		ret = formatter.JSON
	case "yaml":
		ret = formatter.YAML
	default:
		return nil, errors.Errorf("Unknown format %s", format)
	}

	return ret, nil

}
