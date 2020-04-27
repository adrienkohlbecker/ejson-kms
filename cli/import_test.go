package cli

import (
	"bytes"
	"fmt"
	"testing"

	mock_kms "github.com/adrienkohlbecker/ejson-kms/kms/mock"
	"github.com/stretchr/testify/assert"
)

func TestImport(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {

		cmd := importCmd()
		cmd.SetArgs([]string{"--path=does-not-exist"})
		cmd.SetOutput(&bytes.Buffer{})

		err := cmd.Execute()
		if assert.Error(t, err) {
			assert.Equal(t, err.Error(), "Invalid path: Unable to find secrets file at does-not-exist: stat does-not-exist: no such file or directory")
		}

	})

	t.Run("no argument", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := importCmd()
			cmd.SetArgs([]string{"--path", storePath})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Invalid name: No argument provided")
			}

		})

	})

	t.Run("invalid values in env file", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := importCmd()
			cmd.SetArgs([]string{"--path", storePath, testDataInvalidEnv})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Invalid name: Invalid format for name: must be lowercase, can contain letters, digits and underscores, and cannot start with a number.")
			}

		})

	})

	t.Run("env file does not exist", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := importCmd()
			cmd.SetArgs([]string{"--path", storePath, "./testdata/not-a-file.env"})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Unable to load import file: open ./testdata/not-a-file.env: no such file or directory")
			}

		})

	})

	t.Run("invalid json", func(t *testing.T) {

		withTempStore(t, testDataInvalid, func(storePath string) {

			cmd := importCmd()
			cmd.SetArgs([]string{"--path", storePath, testName})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), fmt.Sprintf("Unable to load JSON: Unable to decode Store at %s: unexpected end of JSON input", storePath))
			}

		})

	})

	t.Run("name already exists", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {
			out := &bytes.Buffer{}

			cmd := importCmd()
			cmd.SetArgs([]string{"--path", storePath, testDataValidEnv})
			cmd.SetOutput(out)

			err := cmd.Execute()
			if assert.NoError(t, err) {
				assert.Contains(t, out.String(), "Skipping secret: A secret with the same name already exists. Use the `rotate` command")
			}
		})

	})

	t.Run("working", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := importCmd()
			cmd.SetArgs([]string{"--path", storePath, testDataValidEnv})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("GenerateDataKey", testKmsKeyID, map[string]*string{"Secret": &testName}).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()
			client.On("Decrypt", testKeyCiphertext, map[string]*string{"Secret": &testName}).Return(testKmsKeyID, testKeyPlaintext, nil).Once()

			// withStdin(t, "password\n", func() {

			// 	withMockKmsClient(t, client, func() {
			// 		err := cmd.Execute()
			// 		assert.NoError(t, err)
			// 	})

			// 	store, err := model.Load(storePath)
			// 	assert.NoError(t, err)
			// 	items, err := store.ExportPlaintext(client)
			// 	assert.NoError(t, err)

			// 	item, ok := <-items
			// 	assert.True(t, ok)
			// 	_, ok = <-items
			// 	assert.False(t, ok)

			// 	assert.Equal(t, item.Name, testName)
			// 	assert.Equal(t, item.Plaintext, "password")

			// })

		})

	})

}
