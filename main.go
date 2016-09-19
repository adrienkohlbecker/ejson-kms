package main

import (
	"fmt"
	"os"

	"github.com/adrienkohlbecker/ejson-kms/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
