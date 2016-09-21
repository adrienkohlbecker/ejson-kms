package utils

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadFromFile(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		tmpfile, goErr := ioutil.TempFile(os.TempDir(), "read-from-file")
		assert.NoError(t, goErr)

		_, goErr = tmpfile.WriteString("I'm in your file\n  \n \n")
		assert.NoError(t, goErr)
		goErr = tmpfile.Sync()
		assert.NoError(t, goErr)
		_, goErr = tmpfile.Seek(0, 0)
		assert.NoError(t, goErr)

		contents, err := ReadFromFile(tmpfile)
		assert.NoError(t, err)
		assert.Contains(t, contents, "I'm in your file")

		goErr = tmpfile.Close()
		assert.NoError(t, goErr)
		goErr = os.Remove(tmpfile.Name())
		assert.NoError(t, goErr)

	})

	t.Run("closed fd", func(t *testing.T) {

		tmpfile, goErr := ioutil.TempFile(os.TempDir(), "read-from-file")
		assert.NoError(t, goErr)
		goErr = tmpfile.Close()
		assert.NoError(t, goErr)

		_, err := ReadFromFile(tmpfile)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to read from file")
		}

		goErr = os.Remove(tmpfile.Name())
		assert.NoError(t, goErr)

	})

}

func captureStderr(t *testing.T, f func()) string {

	original := os.Stderr
	r, w, err := os.Pipe()
	assert.NoError(t, err)

	os.Stderr = w
	f()
	os.Stderr = original

	err = w.Close()
	assert.NoError(t, err)

	b, err := ioutil.ReadAll(r)
	assert.NoError(t, err)

	return string(b)

}
