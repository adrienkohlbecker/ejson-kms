package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode(t *testing.T) {

	encrypted := &encrypted{keyCiphertext: []byte("keyCiphertext"), ciphertext: []byte("ciphertext")}
	out := encrypted.encode()
	assert.Equal(t, out, "EJK1];a2V5Q2lwaGVydGV4dA==;Y2lwaGVydGV4dA==")

}

func TestDecode(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		input := "EJK1];a2V5Q2lwaGVydGV4dA==;Y2lwaGVydGV4dA=="
		encrypted, err := decode(input)
		assert.NoError(t, err)
		assert.Equal(t, encrypted.ciphertext, []byte("ciphertext"))
		assert.Equal(t, encrypted.keyCiphertext, []byte("keyCiphertext"))

	})

	t.Run("invalid format", func(t *testing.T) {

		_, err := decode("")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

		_, err = decode("EJK1];abc")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

		_, err = decode("EJK1];abc;def;ghi")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

		_, err = decode("abc;def;ghi")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

	})

	t.Run("invalid base64", func(t *testing.T) {

		_, err := decode("EJK1];YWJj@@@@;YWJj")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to base64 decode keyCiphertext")
		}

		_, err = decode("EJK1];YWJj;YWJj@@@")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to base64 decode ciphertext")
		}

	})

}
