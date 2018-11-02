package main

import (
	"fmt"
	"os"

	"github.com/adrienkohlbecker/ejson-kms/cli"
	"github.com/go-errors/errors"
)

func main() {

	err := cli.App().Execute()
	if err != nil {

		// Error contents is already printed out by cobra

		enableDebug := os.Getenv("EJSON_KMS_DEBUG") == "1"
		errStack, ok := err.(*errors.Error)

		if ok && enableDebug {
			fmt.Println("")
			fmt.Println(string(errStack.Stack()))
		}

		os.Exit(1)

	}
}
