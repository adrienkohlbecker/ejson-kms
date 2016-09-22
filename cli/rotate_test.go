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

func TestRotate(t *testing.T) {

	t.Run("invalid path", func(t *testing.T) {

		cmd := rotateCmd()
		cmd.SetArgs([]string{"--path=does-not-exist"})
		cmd.SetOutput(&bytes.Buffer{})

		err := cmd.Execute()
		if assert.Error(t, err) {
			assert.Equal(t, err.Error(), "Invalid path: Unable to find secrets file at does-not-exist: stat does-not-exist: no such file or directory")
		}

	})

	t.Run("no argument", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := rotateCmd()
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

			cmd := rotateCmd()
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

			cmd := rotateCmd()
			cmd.SetArgs([]string{"--path", storePath, testName})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), fmt.Sprintf("Unable to load JSON: Unable to decode Store at %s: unexpected end of JSON input", storePath))
			}

		})

	})

	t.Run("name does not exists", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := rotateCmd()
			cmd.SetArgs([]string{"--path", storePath, testName})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "No secret with the given name has been found. Use the `add` command")
			}

		})

	})

	t.Run("with stdin error", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			cmd := rotateCmd()
			cmd.SetArgs([]string{"--path", storePath, testName})
			cmd.SetOutput(&bytes.Buffer{})

			withStdinError(t, func() {
				err := cmd.Execute()
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), "Unable to read from stdin")
				}
			})

		})

	})

	t.Run("with kms init error", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			cmd := rotateCmd()
			cmd.SetArgs([]string{"--path", storePath, testName})
			cmd.SetOutput(&bytes.Buffer{})

			withStdin(t, "password\n", func() {
				withKMSNewClientError(t, func() {
					err := cmd.Execute()
					if assert.Error(t, err) {
						assert.Equal(t, err.Error(), "Unable to initialize AWS client: testing errors")
					}
				})
			})

		})

	})

	t.Run("with kms decrypt error", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			cmd := rotateCmd()
			cmd.SetArgs([]string{"--path", storePath, testName})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("Decrypt", testKeyCiphertext, map[string]*string{"Secret": &testName}).Return("", "", errors.New("testing errors")).Once()

			withStdin(t, "password\n", func() {
				withMockKmsClient(t, client, func() {
					err := cmd.Execute()
					if assert.Error(t, err) {
						assert.Equal(t, err.Error(), "Unable to rotate secret: Unable to decrypt secret: Unable to decrypt key ciphertext: testing errors")
					}
				})
			})

		})

	})

	t.Run("working", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			cmd := rotateCmd()
			cmd.SetArgs([]string{"--path", storePath, testName})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("Decrypt", testKeyCiphertext, map[string]*string{"Secret": &testName}).Return(testKmsKeyID, testKeyPlaintext, nil).Twice()
			client.On("GenerateDataKey", testKmsKeyID, map[string]*string{"Secret": &testName}).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

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

				assert.Equal(t, item.Name, testName)
				assert.Equal(t, item.Plaintext, "password")

			})

		})

	})

}
