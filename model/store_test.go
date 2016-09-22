package model

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	crypto_mock "github.com/adrienkohlbecker/ejson-kms/crypto/mock"
	kms_mock "github.com/adrienkohlbecker/ejson-kms/kms/mock"
	"github.com/stretchr/testify/assert"
)

const (
	testKeyID         = "my-key-id"
	testKeyPlaintext  = "-abcdefabcdefabcdefabcdefabcdef-"
	testKeyCiphertext = "ciphertextblob"
	testConstantNonce = "abcdefabcdefabcdefabcdef"
	testPlaintext     = "abcdef"
	testCiphertext    = "EJK1;Y2lwaGVydGV4dGJsb2I=;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmlPmP6IWfK7WJMuXVi8aQ7TZu8vCkVA=="
	testDescription   = "Some description."
	testPlaintext2    = "ghijklm"
	testCiphertext2   = "EJK1;Y2lwaGVydGV4dGJsb2I=;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVm4iKh5QPWblMQEKL6IaIRtjBk+P6qXpI="
	testDescription2  = "Some other description."

	testKeyID2             = "my-other-key"
	testKeyPlaintext2      = "-123456789012345678901234567890-"
	testKeyCiphertext2     = "anotherciphertextblob"
	testCiphertextOtherKey = "EJK1;YW5vdGhlcmNpcGhlcnRleHRibG9i;YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmQV4vWDZmRgWgHcfvkFd0yP7uEoH1vw=="
)

var (
	testName     = "my_cred"
	testName2    = "my_other_cred"
	testContext  = map[string]*string{"ABC": nil}
	testContext1 = map[string]*string{"ABC": nil, "Secret": &testName}
	testContext2 = map[string]*string{"ABC": nil, "Secret": &testName2}
)

func TestNewStore(t *testing.T) {

	store := NewStore(testKeyID, testContext)
	assert.Equal(t, testKeyID, store.KMSKeyID)
	assert.Equal(t, 1, store.Version)
	assert.Equal(t, testContext, store.EncryptionContext)
	assert.Equal(t, []*Secret{}, store.Secrets)

}

func TestLoad(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		j, err := Load("./testdata/empty.json")
		assert.NoError(t, err)
		assert.NotNil(t, j)

		assert.NotEmpty(t, j.KMSKeyID)
		assert.NotEmpty(t, j.EncryptionContext)
		assert.Equal(t, *j.EncryptionContext["KEY"], "VALUE")
		if assert.Equal(t, len(j.Secrets), 1) {

			cred := j.Secrets[0]
			assert.Equal(t, cred.Name, "test_cred")
			assert.Equal(t, cred.Description, "Some Description")
			assert.NotEmpty(t, cred.Ciphertext)

		}

	})

	t.Run("invalid json", func(t *testing.T) {

		_, err := Load("./testdata/invalid.json")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decode Store")
		}

	})

	t.Run("no file", func(t *testing.T) {

		_, err := Load("does-not-exist")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to read file")
		}

	})

}

func TestContains(t *testing.T) {

	j := &Store{Secrets: []*Secret{
		&Secret{Name: "test_cred"},
	}}

	assert.True(t, j.Contains("test_cred"))
	assert.False(t, j.Contains("other"))

}

func TestSave(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		j, err := Load("./testdata/empty.json")
		assert.NoError(t, err)
		assert.NotNil(t, j)

		tmpfile, goErr := ioutil.TempFile(os.TempDir(), "read-from-file")
		assert.NoError(t, goErr)
		goErr = tmpfile.Close()
		assert.NoError(t, goErr)

		err = j.Save(tmpfile.Name())
		assert.NoError(t, err)

		goErr = os.Remove(tmpfile.Name())
		assert.NoError(t, goErr)

	})

	t.Run("write error", func(t *testing.T) {

		dir, goErr := ioutil.TempDir(os.TempDir(), "read-from-file")
		assert.NoError(t, goErr)

		j := &Store{}
		err := j.Save(dir)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to write file")
		}

		goErr = os.Remove(dir)
		assert.NoError(t, goErr)

	})

}

func TestAdd(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		store := NewStore(testKeyID, testContext)

		crypto_mock.WithConstRandReader(testConstantNonce, func() {
			err := store.Add(client, testPlaintext, testName, testDescription)
			assert.NoError(t, err)
		})

		if assert.Len(t, store.Secrets, 1) {
			cred := store.Secrets[0]
			assert.Equal(t, cred.Name, testName)
			assert.Equal(t, cred.Description, testDescription)
			assert.Equal(t, cred.Ciphertext, testCiphertext)
		}

	})

	t.Run("fails", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("GenerateDataKey", testKeyID, testContext1).Return("", "", errors.New("testing errors")).Once()
		store := NewStore(testKeyID, testContext)

		err := store.Add(client, testPlaintext, testName, testDescription)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to generate data key")
		}

	})

}

func TestExportPlaintext(t *testing.T) {

	store := NewStore(testKeyID, testContext)

	t.Run("empty", func(t *testing.T) {

		client := &kms_mock.Client{}

		items, err := store.ExportPlaintext(client)
		assert.NoError(t, err)

		_, open := <-items
		assert.False(t, open)

	})

	t.Run("working", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return(testKeyID, testKeyPlaintext, nil).Once()
		client.On("Decrypt", testKeyCiphertext, testContext2).Return(testKeyID, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext2).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		err := store.Add(client, testPlaintext, testName, testDescription)
		assert.NoError(t, err)

		err = store.Add(client, testPlaintext2, testName2, testDescription2)
		assert.NoError(t, err)

		items, err := store.ExportPlaintext(client)
		assert.NoError(t, err)

		item, open := <-items
		assert.True(t, open)
		assert.Equal(t, item.Name, testName)
		assert.Equal(t, item.Plaintext, testPlaintext)

		item, open = <-items
		assert.True(t, open)
		assert.Equal(t, item.Name, testName2)
		assert.Equal(t, item.Plaintext, testPlaintext2)

		_, open = <-items
		assert.False(t, open)

	})

	t.Run("fails", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return("", "", errors.New("testing errors")).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		err := store.Add(client, testPlaintext, testName, testDescription)
		assert.NoError(t, err)

		items, err := store.ExportPlaintext(client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt key ciphertext")
		}

		_, open := <-items
		assert.False(t, open)

	})

}

func TestFind(t *testing.T) {

	cred := &Secret{Name: "my_cred"}
	store := &Store{Secrets: []*Secret{cred}}

	assert.Equal(t, store.Find("my_cred"), cred)
	assert.Nil(t, store.Find("other"))

}

func TestRotateKMSKey(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return(testKeyID, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID2, testContext1).Return(testKeyCiphertext2, testKeyPlaintext2, nil).Once()

		store := NewStore(testKeyID, testContext)

		crypto_mock.WithConstRandReader(testConstantNonce, func() {
			err := store.Add(client, testPlaintext, testName, testDescription)
			assert.NoError(t, err)

			err = store.RotateKMSKey(client, testKeyID2)
			assert.NoError(t, err)
		})

		item := store.Find(testName)
		assert.Equal(t, item.Ciphertext, testCiphertextOtherKey)
		assert.Equal(t, store.KMSKeyID, testKeyID2)

	})

	t.Run("decrypt error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return("", "", errors.New("testing errors")).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		store := NewStore(testKeyID, testContext)

		err := store.Add(client, testPlaintext, testName, testDescription)
		assert.NoError(t, err)

		err = store.RotateKMSKey(client, testKeyID2)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt secret")
		}

	})

	t.Run("encrypt error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return(testKeyID, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID2, testContext1).Return("", "", errors.New("testing errors")).Once()

		store := NewStore(testKeyID, testContext)

		err := store.Add(client, testPlaintext, testName, testDescription)
		assert.NoError(t, err)

		err = store.RotateKMSKey(client, testKeyID2)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to encrypt secret")
		}

	})

}

func TestRotate(t *testing.T) {

	t.Run("working", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return(testKeyID, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Twice()

		store := NewStore(testKeyID, testContext)

		crypto_mock.WithConstRandReader(testConstantNonce, func() {
			err := store.Add(client, testPlaintext, testName, testDescription)
			assert.NoError(t, err)

			err = store.Rotate(client, testName, testPlaintext2)
			assert.NoError(t, err)
		})

		item := store.Find(testName)
		assert.Equal(t, item.Ciphertext, testCiphertext2)

	})

	t.Run("cant find name", func(t *testing.T) {

		client := &kms_mock.Client{}

		store := NewStore(testKeyID, testContext)
		err := store.Rotate(client, testName, testPlaintext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to find")
		}

	})

	t.Run("same value", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return(testKeyID, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		store := NewStore(testKeyID, testContext)

		err := store.Add(client, testPlaintext, testName, testDescription)
		assert.NoError(t, err)

		err = store.Rotate(client, testName, testPlaintext)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Trying to rotate a secret and giving the same value")
		}

	})

	t.Run("decrypt error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return("", "", errors.New("testing errors")).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()

		store := NewStore(testKeyID, testContext)

		err := store.Add(client, testPlaintext, testName, testDescription)
		assert.NoError(t, err)

		err = store.Rotate(client, testName, testPlaintext2)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decrypt secret")
		}

	})

	t.Run("encrypt error", func(t *testing.T) {

		client := &kms_mock.Client{}
		client.On("Decrypt", testKeyCiphertext, testContext1).Return(testKeyID, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return(testKeyCiphertext, testKeyPlaintext, nil).Once()
		client.On("GenerateDataKey", testKeyID, testContext1).Return("", "", errors.New("testing errors")).Once()

		store := NewStore(testKeyID, testContext)

		err := store.Add(client, testPlaintext, testName, testDescription)
		assert.NoError(t, err)

		err = store.Rotate(client, testName, testPlaintext2)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to encrypt secret")
		}

	})
}
