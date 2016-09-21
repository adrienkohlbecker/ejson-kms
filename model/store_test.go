package model

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testContext = map[string]*string{"ABC": nil}

const (
	testKeyID         = "my-key-id"
)

func TestNewStore(t *testing.T) {

	store := NewStore(testKeyID, testContext)
	assert.Equal(t, testKeyID, store.KMSKeyID)
	assert.Equal(t, 1, store.Version)
	assert.Equal(t, testContext, store.EncryptionContext)
	assert.Equal(t, []Credential{}, store.Credentials)

}

func TestLoad(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		j, err := Load("./testdata/empty.json")
		assert.NoError(t, err)
		assert.NotNil(t, j)

		assert.NotEmpty(t, j.KMSKeyID)
		assert.NotEmpty(t, j.EncryptionContext)
		assert.Equal(t, *j.EncryptionContext["KEY"], "VALUE")
		if assert.Equal(t, len(j.Credentials), 1) {

			cred := j.Credentials[0]
			assert.Equal(t, cred.Name, "test_cred")
			assert.Equal(t, cred.Description, "Some Description")
			assert.Equal(t, time.Date(2016, 9, 19, 14, 21, 22, 0, time.UTC), cred.AddedAt)
			assert.Nil(t, cred.RotatedAt)
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

	j := &Store{Credentials: []Credential{
		Credential{Name: "test_cred"},
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
