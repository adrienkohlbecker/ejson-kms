package cli

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	mock_kms "github.com/adrienkohlbecker/ejson-kms/kms/mock"
	"github.com/stretchr/testify/assert"
)

func TestExport(t *testing.T) {

	t.Run("invalid path", func(t *testing.T) {

		cmd := exportCmd()
		cmd.SetArgs([]string{"--path=does-not-exist"})
		cmd.SetOutput(&bytes.Buffer{})

		err := cmd.Execute()
		if assert.Error(t, err) {
			assert.Equal(t, err.Error(), "Invalid path: Unable to find secrets file at does-not-exist: stat does-not-exist: no such file or directory")
		}

	})

	t.Run("invalid json", func(t *testing.T) {

		withTempStore(t, testDataInvalid, func(storePath string) {

			cmd := exportCmd()
			cmd.SetArgs([]string{"--path", storePath})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), fmt.Sprintf("Unable to load JSON: Unable to decode Store at %s: unexpected end of JSON input", storePath))
			}

		})

	})

	t.Run("invalid formatter", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := exportCmd()
			cmd.SetArgs([]string{"--path", storePath, "--format", "does-not-exist"})
			cmd.SetOutput(&bytes.Buffer{})

			err := cmd.Execute()
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "Invalid formatter: Unknown format does-not-exist")
			}

		})

	})

	t.Run("with kms init error", func(t *testing.T) {

		withTempStore(t, testDataEmpty, func(storePath string) {

			cmd := exportCmd()
			cmd.SetArgs([]string{"--path", storePath})
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

			cmd := exportCmd()
			cmd.SetArgs([]string{"--path", storePath})
			cmd.SetOutput(&bytes.Buffer{})

			client := &mock_kms.Client{}
			client.On("Decrypt", testKeyCiphertext, map[string]*string{"Secret": &testName}).Return("", "", errors.New("testing errors")).Once()

			withMockKmsClient(t, client, func() {
				err := cmd.Execute()
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), "Unable to export items: Unable to decrypt key ciphertext: testing errors")
				}
			})

		})

	})

	t.Run("working", func(t *testing.T) {

		withTempStore(t, testDataOneCredential, func(storePath string) {

			out := &bytes.Buffer{}

			cmd := exportCmd()
			cmd.SetArgs([]string{"--path", storePath})
			cmd.SetOutput(out)

			client := &mock_kms.Client{}
			client.On("Decrypt", testKeyCiphertext, map[string]*string{"Secret": &testName}).Return(testKmsKeyID, testKeyPlaintext, nil).Once()

			withMockKmsClient(t, client, func() {
				err := cmd.Execute()
				if assert.NoError(t, err) {
					assert.Equal(t, out.String(), "export SECRET=\"abcdef\"\n")
				}
			})

		})

	})

}
