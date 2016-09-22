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

func TestRotateKMSKey(t *testing.T) {

	t.Run("invalid path", func(t *testing.T) {

		cmd := rotateKMSKeyCmd()
		cmd.SetArgs([]string{"--path=does-not-exist"})
		cmd.SetOutput(&bytes.Buffer{})

		err := cmd.Execute()
		if assert.Error(t, err) {
			assert.Equal(t, err.Error(), "Invalid path: Unable to find secrets file at does-not-exist: stat does-not-exist: no such file or directory")
		}

	})

	t.Run("no argument", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := rotateKMSKeyCmd()
			cmd.SetArgs([]string{"--path", storePath})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Invalid new KMS Key ID: No argument provided")
			}

		})

	})

	t.Run("invalid json", func(t *testing.T) {

		withTempStore(t, testDataInvalid, func(storePath string) {

			cmd := rotateKMSKeyCmd()
			cmd.SetArgs([]string{"--path", storePath, testKmsKeyID2})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), fmt.Sprintf("Unable to load JSON: Unable to decode Store at %s: unexpected end of JSON input", storePath))
			}

		})

	})

	t.Run("with kms init error", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := rotateKMSKeyCmd()
			cmd.SetArgs([]string{"--path", storePath, testKmsKeyID2})
			cmd.SetOutput(&bytes.Buffer{})

			withKMSNewClientError(t, func() {
				err := cmd.Execute()
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), "Unable to initialize AWS client: testing errors")
				}
			})

		})

	})

	t.Run("with kms decrypt error", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			cmd := rotateKMSKeyCmd()
			cmd.SetArgs([]string{"--path", storePath, testKmsKeyID2})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("Decrypt", testKeyCiphertext, map[string]*string{"Secret": &testName}).Return("", "", errors.New("testing errors")).Once()

			withMockKmsClient(t, client, func() {
				err := cmd.Execute()
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), "Unable to rotate the KMS key: Unable to decrypt secret: secret: Unable to decrypt key ciphertext: testing errors")
				}
			})

		})

	})

	t.Run("working", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			cmd := rotateKMSKeyCmd()
			cmd.SetArgs([]string{"--path", storePath, testKmsKeyID2})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("Decrypt", testKeyCiphertext, map[string]*string{"Secret": &testName}).Return(testKmsKeyID, testKeyPlaintext, nil).Once()
			client.On("GenerateDataKey", testKmsKeyID2, map[string]*string{"Secret": &testName}).Return(testKeyCiphertext2, testKeyPlaintext2, nil).Once()
			client.On("Decrypt", testKeyCiphertext2, map[string]*string{"Secret": &testName}).Return(testKmsKeyID2, testKeyPlaintext2, nil).Once()

			withMockKmsClient(t, client, func() {
				err := cmd.Execute()
				assert.NoError(t, err)
			})

			store, err := model.Load(storePath)
			assert.NoError(t, err)

			assert.Equal(t, store.KMSKeyID, testKmsKeyID2)

			items, err := store.ExportPlaintext(client)
			assert.NoError(t, err)

			item, ok := <-items
			assert.True(t, ok)
			_, ok = <-items
			assert.False(t, ok)

			assert.Equal(t, item.Name, testName)
			assert.Equal(t, item.Plaintext, "abcdef")

		})

	})

}
