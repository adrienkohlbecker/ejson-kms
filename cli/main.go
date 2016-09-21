package cli

import "github.com/adrienkohlbecker/ejson-kms/kms"

var (
	version string
	sha1    string
	builtAt string

	// for mocking in tests
	kmsNewClient = kms.NewClient
)
