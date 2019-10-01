package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/adrienkohlbecker/ejson-kms/formatter"
	"github.com/stretchr/testify/assert"
)

func TestValidSecretsPath(t *testing.T) {

	t.Run("empty path", func(t *testing.T) {

		err := ValidSecretsPath("")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "No path provided")
		}

	})

	t.Run("unexisting path", func(t *testing.T) {

		err := ValidSecretsPath("not-a-real-path")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to find secrets file")
		}

	})

	t.Run("directory", func(t *testing.T) {

		dir, goErr := ioutil.TempDir(os.TempDir(), "valid-secrets-path")
		assert.NoError(t, goErr)

		err := ValidSecretsPath(dir)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Secrets file is a directory")
		}

		goErr = os.Remove(dir)
		assert.NoError(t, goErr)

	})

	t.Run("valid path", func(t *testing.T) {

		tmpfile, goErr := ioutil.TempFile(os.TempDir(), "valid-secrets-path")
		assert.NoError(t, goErr)

		err := ValidSecretsPath(tmpfile.Name())
		assert.NoError(t, err)

		goErr = tmpfile.Close()
		assert.NoError(t, goErr)
		goErr = os.Remove(tmpfile.Name())
		assert.NoError(t, goErr)

	})

}

func TestValidNewSecretsPath(t *testing.T) {

	t.Run("empty path", func(t *testing.T) {

		err := ValidNewSecretsPath("")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "No path provided")
		}

	})

	t.Run("valid unexisting path", func(t *testing.T) {

		err := ValidNewSecretsPath("not-a-real-path")
		assert.NoError(t, err)

	})

	t.Run("existing path", func(t *testing.T) {

		tmpfile, goErr := ioutil.TempFile(os.TempDir(), "valid-secrets-path")
		assert.NoError(t, goErr)

		err := ValidNewSecretsPath(tmpfile.Name())
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "A file already exists")
		}

		goErr = tmpfile.Close()
		assert.NoError(t, goErr)
		goErr = os.Remove(tmpfile.Name())
		assert.NoError(t, goErr)

	})

}

func TestValidName(t *testing.T) {

	valid := []string{"test", "test123", "_test_123_foo"}
	for _, item := range valid {

		t.Run(fmt.Sprintf("valid name=%#v", item), func(t *testing.T) {

			err := ValidName(item)
			assert.NoError(t, err)

		})

	}

	invalid := []string{"", "1abc", "ABC", "ABC/DEF"}
	for _, item := range invalid {

		t.Run(fmt.Sprintf("invalid name=%#v", item), func(t *testing.T) {

			err := ValidName(item)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "Invalid format for name")
			}

		})
	}

}

func TestHasOneArgument(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		value, err := HasOneArgument([]string{"abc"})
		assert.NoError(t, err)
		assert.Equal(t, value, "abc")

	})

	t.Run("empty value", func(t *testing.T) {

		_, err := HasOneArgument([]string{""})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Empty argument")
		}

	})

	t.Run("empty", func(t *testing.T) {

		_, err := HasOneArgument([]string{})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "No argument provided")
		}

	})

	t.Run("more than one", func(t *testing.T) {

		_, err := HasOneArgument([]string{"abc", "def"})
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "More than one argument provided")
		}

	})

}

func TestValidEncryptionContext(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		def := "DEF"
		jkl := "JKL"

		value, err := ValidEncryptionContext([]string{"ABC=DEF", "GHI=JKL"})
		assert.NoError(t, err)
		assert.Exactly(t, map[string]*string{"ABC": &def, "GHI": &jkl}, value)

	})

	invalid := []string{"ABC", "ABC=DEF=GHI"}
	for _, item := range invalid {

		t.Run(fmt.Sprintf("invalid %s", item), func(t *testing.T) {

			_, err := ValidEncryptionContext([]string{item})
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "Invalid format for encryption context")
			}

		})

	}

}

func TestValidFormatter(t *testing.T) {

	valid := map[string]formatter.Formatter{
		"json":          formatter.JSON,
		"bash":          formatter.Bash,
		"bash-ifnotset": formatter.BashIfNotSet,
		"bash-ifempty":  formatter.BashIfEmpty,
		"dotenv":        formatter.Dotenv,
		"yaml":          formatter.YAML,
	}

	for value, f := range valid {

		t.Run(fmt.Sprintf("valid %s", value), func(t *testing.T) {

			ret, err := ValidFormatter(value)
			assert.NoError(t, err)
			assert.Equal(t, reflect.ValueOf(f).Pointer(), reflect.ValueOf(ret).Pointer())

		})

	}

	t.Run("invalid", func(t *testing.T) {

		_, err := ValidFormatter("invalid")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unknown format")
		}

	})

}
