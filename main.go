package main

import (
	"fmt"
	"os"

	"github.com/adrienkohlbecker/ejson-kms/cli"
	"github.com/adrienkohlbecker/errors"
)

func main() {

	err := cli.App().Execute()
	if err != nil {

		// Error contents is already printed out by cobra

		enableDebug := os.Getenv("EJSON_KMS_DEBUG") == "1"
		errStack, ok := err.(errors.Error)

		if ok && enableDebug {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintln(os.Stderr, string(errStack.Stack()))
		}

		os.Exit(1)

	}
}
