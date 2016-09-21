package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {

	out := &bytes.Buffer{}

	version = "1.0.0"
	sha1 = "git hash"
	builtAt = "(built at)"

	cmd := versionCmd()
	cmd.SetOutput(out)

	err := cmd.Execute()
	assert.NoError(t, err)

	assert.Equal(t, out.String(), "ejson-kms 1.0.0 (git hash) built (built at)\n")

}
