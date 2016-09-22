package utils

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadPassword(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		withStdin(t, "testing 123\n", func() {

			contents, err := ReadPassword()
			assert.NoError(t, err)
			assert.Contains(t, contents, "testing 123")

		})

	})

	t.Run("valid terminal", func(t *testing.T) {

		original := isTerminal
		isTerminal = func(fd int) bool { return true }

		withStdin(t, "testing 123\n", func() {

			contents, err := ReadPassword()
			assert.NoError(t, err)
			assert.Contains(t, contents, "testing 123")

		})

		isTerminal = original

	})

	t.Run("closed fd", func(t *testing.T) {

		withStdinError(t, func() {

			_, err := ReadPassword()
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "Unable to read from stdin")
			}

		})

	})

}

func withStdin(t *testing.T, str string, f func()) {

	tmpfile, err := ioutil.TempFile(os.TempDir(), "read-from-file")
	assert.NoError(t, err)

	_, err = tmpfile.WriteString(str)
	assert.NoError(t, err)
	err = tmpfile.Sync()
	assert.NoError(t, err)
	_, err = tmpfile.Seek(0, 0)
	assert.NoError(t, err)

	original := os.Stdin
	os.Stdin = tmpfile

	f()

	os.Stdin = original

	err = tmpfile.Close()
	assert.NoError(t, err)
	err = os.Remove(tmpfile.Name())
	assert.NoError(t, err)

}

func withStdinError(t *testing.T, f func()) {

	tmpfile, err := ioutil.TempFile(os.TempDir(), "read-from-file")
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)

	original := os.Stdin
	os.Stdin = tmpfile

	f()

	os.Stdin = original

	err = os.Remove(tmpfile.Name())
	assert.NoError(t, err)

}
