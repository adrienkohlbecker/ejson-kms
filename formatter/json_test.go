package formatter

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/adrienkohlbecker/ejson-kms/model"
	"github.com/stretchr/testify/assert"
)

func TestJSON(t *testing.T) {

	var b bytes.Buffer
	items := make(chan Item, 2)
	items <- Item{
		Credential: model.Credential{
			Name: "my_credential",
		},
		Plaintext: "my value",
	}
	items <- Item{
		Credential: model.Credential{
			Name: "another_one",
		},
		Plaintext: "string with \"quotes\"",
	}
	close(items)

	err := JSON(&b, items)
	assert.NoError(t, err)
	exported, goErr := ioutil.ReadAll(&b)
	assert.NoError(t, goErr)

	expected, goErr := ioutil.ReadFile("./testdata/json.json")
	assert.NoError(t, goErr)
	assert.Equal(t, string(expected), string(exported))

}
