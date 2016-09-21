package cli

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {

	t.Run("existing path", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {
			cmd := initCmd()
			cmd.SetArgs([]string{"--path", storePath})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "Invalid path: A file already exists at")
			}
		})

	})

	t.Run("invalid encryption context", func(t *testing.T) {

		withTempPath(t, func(tempPath string) {

			cmd := initCmd()
			cmd.SetArgs([]string{"--path", tempPath, "--encryption-context", "A"})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Invalid encryption context: Invalid format for encryption context")
			}

		})

	})

	t.Run("no kms key", func(t *testing.T) {

		withTempPath(t, func(tempPath string) {

			cmd := initCmd()
			cmd.SetArgs([]string{"--path", tempPath})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "No KMS Key ID provided")
			}

		})

	})

	t.Run("working", func(t *testing.T) {

		withTempPath(t, func(tempPath string) {

			cmd := initCmd()
			cmd.SetArgs([]string{"--path", tempPath, "--kms-key-id", testKmsKeyID})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.NoError(t, err) {
				result, err := ioutil.ReadFile(tempPath)
				assert.NoError(t, err)

				expected, err := ioutil.ReadFile(testDataEmpty)
				assert.NoError(t, err)

				assert.Equal(t, string(result), string(expected))

				err = os.Remove(tempPath)
				assert.NoError(t, err)

			}

		})

	})

}
