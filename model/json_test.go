package model

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestImport(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		j, err := Import("./testdata/empty.json")
		assert.NoError(t, err)
		assert.NotNil(t, j)

		assert.NotEmpty(t, j.KMSKeyArn)
		assert.NotEmpty(t, j.Context)
		assert.Equal(t, *j.Context["KEY"], "VALUE")
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

		_, err := Import("./testdata/invalid.json")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to decode JSON")
		}

	})

	t.Run("no file", func(t *testing.T) {

		_, err := Import("does-not-exist")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to read file")
		}

	})

}

func TestNameExists(t *testing.T) {

	j := &JSON{Credentials: []Credential{
		Credential{Name: "test_cred"},
	}}

	assert.True(t, j.NameExists("test_cred"))
	assert.False(t, j.NameExists("other"))

}

func TestExport(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		j, err := Import("./testdata/empty.json")
		assert.NoError(t, err)
		assert.NotNil(t, j)

		tmpfile, goErr := ioutil.TempFile(os.TempDir(), "read-from-file")
		assert.NoError(t, goErr)
		goErr = tmpfile.Close()
		assert.NoError(t, goErr)

		err = j.Export(tmpfile.Name())
		assert.NoError(t, err)

		goErr = os.Remove(tmpfile.Name())
		assert.NoError(t, goErr)

	})

	t.Run("write error", func(t *testing.T) {

		dir, goErr := ioutil.TempDir(os.TempDir(), "read-from-file")
		assert.NoError(t, goErr)

		j := &JSON{}
		err := j.Export(dir)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to write file")
		}

		goErr = os.Remove(dir)
		assert.NoError(t, goErr)

	})

}
