package cli

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	mock_kms "github.com/adrienkohlbecker/ejson-kms/kms/mock"
	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/stretchr/testify/assert"
)

func TestAdd(t *testing.T) {

	t.Run("invalid path", func(t *testing.T) {

		cmd := addCmd()
		cmd.SetArgs([]string{"--path=does-not-exist"})
		cmd.SetOutput(&bytes.Buffer{})

		err := cmd.Execute()
		if assert.Error(t, err) {
			assert.Equal(t, err.Error(), "Invalid path: Unable to find secrets file at does-not-exist: stat does-not-exist: no such file or directory")
		}

	})

	t.Run("no argument", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Invalid name: No argument provided")
			}

		})

	})

	t.Run("invalid name", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath, "123_ABC"})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Invalid name: Invalid format for name: must be lowercase, can contain letters, digits and underscores, and cannot start with a number.")
			}

		})

	})

	t.Run("invalid json", func(t *testing.T) {

		withTempStore(t, testDataInvalid, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath, "secret"})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), fmt.Sprintf("Unable to load JSON: Unable to decode Store at %s: unexpected end of JSON input", storePath))
			}

		})

	})

	t.Run("name already exists", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath, "secret"})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "A secret with the same name already exists. Use the `rotate` command")
			}

		})

	})

	t.Run("with stdin error", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath, "secret"})
			cmd.SetOutput(&bytes.Buffer{})

			withStdinError(t, func() {
				err := cmd.Execute()
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), "Unable to read from stdin: Unable to read from file")
				}
			})

		})

	})

	t.Run("with kms init error", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath, "secret"})
			cmd.SetOutput(&bytes.Buffer{})

			withKMSNewClientError(t, func() {
				err := cmd.Execute()
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), "Unable to initialize AWS client: testing errors")
				}
			})

		})

	})

	t.Run("with kms add error", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath, "secret"})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("GenerateDataKey", testKmsKeyID, map[string]*string{}).Return("", "", errors.New("testing errors")).Once()

			withMockKmsClient(t, client, func() {
				err := cmd.Execute()
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), "Unable to add secret: Unable to generate data key: testing errors")
				}
			})

		})

	})

	t.Run("working", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := addCmd()
			cmd.SetArgs([]string{"--path", storePath, "secret"})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("GenerateDataKey", testKmsKeyID, map[string]*string{}).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()
			client.On("Decrypt", testKeyCiphertext, map[string]*string{}).Return(testKmsKeyID, testKeyPlaintext, nil).Once()

			withStdin(t, "password\n", func() {

				withMockKmsClient(t, client, func() {
					err := cmd.Execute()
					assert.NoError(t, err)
				})

				store, err := model.Load(storePath)
				assert.NoError(t, err)
				items, err := store.ExportPlaintext(client)
				assert.NoError(t, err)

				item, ok := <-items
				assert.True(t, ok)
				_, ok = <-items
				assert.False(t, ok)

				assert.Equal(t, item.Name, "secret")
				assert.Equal(t, item.Plaintext, "password")

			})

		})

	})

}
