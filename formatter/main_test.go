package formatter

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testFormatter(t *testing.T, formatter Formatter, dataPath string) {

	var b bytes.Buffer
	items := make(chan Item, 3)
	items <- Item{
		Name:      "my_secret",
		Plaintext: "my value",
	}
	items <- Item{
		Name:      "another_one",
		Plaintext: "string with \"double\" and 'single' quotes",
	}
	items <- Item{
		Name:      "foobar",
		Plaintext: "string\nwith\nnewlines",
	}
	close(items)

	err := formatter(&b, items)
	assert.NoError(t, err)
	exported, goErr := ioutil.ReadAll(&b)
	assert.NoError(t, goErr)

	expected, goErr := ioutil.ReadFile(dataPath)
	assert.NoError(t, goErr)
	assert.Equal(t, string(expected), string(exported))

}
