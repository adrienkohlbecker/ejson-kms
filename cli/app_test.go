package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApp(t *testing.T) {

	out := &bytes.Buffer{}

	cmd := App()
	cmd.SetArgs([]string{})
	cmd.SetOutput(out)

	err := cmd.Execute()
	if assert.NoError(t, err) {
		assert.Contains(t, out.String(), "Available Commands:")
	}
}
