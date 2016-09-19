package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode(t *testing.T) {

	input := Msg{ciphertext: []byte("ciphertext"), keyCiphertext: []byte("keyCiphertext")}
	out := Encode(input)
	assert.Equal(t, out, "EJK1];a2V5Q2lwaGVydGV4dA==;Y2lwaGVydGV4dA==")

}

func TestDecode(t *testing.T) {

	t.Run("valid", func(t *testing.T) {

		input := "EJK1];a2V5Q2lwaGVydGV4dA==;Y2lwaGVydGV4dA=="
		out, err := Decode(input)
		assert.NoError(t, err)
		assert.Equal(t, out, Msg{ciphertext: []byte("ciphertext"), keyCiphertext: []byte("keyCiphertext")})

	})

	t.Run("invalid format", func(t *testing.T) {

		_, err := Decode("")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

		_, err = Decode("EJK1];abc")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

		_, err = Decode("EJK1];abc;def;ghi")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

		_, err = Decode("abc;def;ghi")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Invalid format for encoded string")
		}

	})

	t.Run("invalid base64", func(t *testing.T) {

		_, err := Decode("EJK1];YWJj@@@@;YWJj")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to base64 decode keyCiphertext")
		}

		_, err = Decode("EJK1];YWJj;YWJj@@@")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Unable to base64 decode ciphertext")
		}

	})

}
