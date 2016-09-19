package utils

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/adrienkohlbecker/ejson-kms/formatter"
	"github.com/adrienkohlbecker/errors"
)

var nameRegexp = regexp.MustCompile("^[a-z_][a-z0-9_]*$")

func ValidCredentialsPath(path string) errors.Error {

	if path == "" {
		return errors.Errorf("No path provided")
	}

	stat, err := os.Stat(path)
	if err != nil {
		return errors.WrapPrefix(err, fmt.Sprintf("Unable to find credentials file at %s", path), 0)
	}

	if stat.IsDir() {
		return errors.Errorf("Credentials file is a directory: %s", path)
	}

	return nil

}

func ValidNewCredentialsPath(path string) errors.Error {

	if path == "" {
		return errors.Errorf("No path provided")
	}

	_, err := os.Stat(path)
	if err == nil {
		return errors.Errorf("A file already exists at %s", path)
	}

	return nil

}

func ValidName(name string) errors.Error {

	if !nameRegexp.MatchString(name) {
		return errors.Errorf("Invalid format for name: must be lowercase, can contain letters, digits and underscores, and cannot start with a number.")
	}

	return nil
}

func HasOneArgument(args []string) (string, errors.Error) {

	var value string
	if len(args) == 1 {
		value = args[0]
	} else if len(args) > 0 {
		return "", errors.Errorf("More than one argument provided")
	} else {
		return "", errors.Errorf("No argument provided")
	}

	return value, nil
}

func ValidContextFromCLI(raw []string) (map[string]*string, errors.Error) {

	context := make(map[string]*string)

	for _, item := range raw {
		splitted := strings.SplitN(item, "=", 2)
		if len(splitted) != 2 {
			return context, errors.Errorf("Invalid format for context")
		}
		context[splitted[0]] = &splitted[1]
	}

	return context, nil
}

func ValidFormatterFromArg(format string) (formatter.Formatter, errors.Error) {

	var ret formatter.Formatter

	switch format {
	case "bash":
		ret = formatter.Bash
	case "dotenv":
		ret = formatter.Dotenv
	case "json":
		ret = formatter.JSON
	default:
		return nil, errors.Errorf("Unknown format %s", format)
	}

	return ret, nil

}
