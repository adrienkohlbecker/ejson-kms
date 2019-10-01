package formatter

import "testing"

func TestBash(t *testing.T) {
	testFormatter(t, Bash, "./testdata/bash")
}

func TestBashExport(t *testing.T) {
	testFormatter(t, BashExport, "./testdata/bash-export")
}
