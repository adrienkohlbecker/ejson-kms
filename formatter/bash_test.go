package formatter

import "testing"

func TestBash(t *testing.T) {
	testFormatter(t, Bash, "./testdata/bash")
}
