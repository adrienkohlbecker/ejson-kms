package formatter

import "testing"

func TestBash(t *testing.T) {
	testFormatter(t, Bash, "./testdata/bash")
}

func TestBashExport(t *testing.T) {
	testFormatter(t, BashExport, "./testdata/bash-export")
}

func TestBashIfNotSet(t *testing.T) {
	testFormatter(t, BashIfNotSet, "./testdata/bash-ifnotset")
}

func TestBashIfEmpty(t *testing.T) {
	testFormatter(t, BashIfEmpty, "./testdata/bash-ifempty")
}
