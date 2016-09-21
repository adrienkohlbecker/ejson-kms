package main

import (
	"fmt"
	"os"

	"github.com/adrienkohlbecker/ejson-kms/cli"
	"github.com/spf13/cobra/doc"
)

func main() {
	header := &doc.GenManHeader{
		Title:   "EJSON-KMS",
		Section: "1",
	}

	app := cli.App()
	err := doc.GenMarkdownTree(app, "./doc/md")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = doc.GenManTree(app, header, "./doc/man")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
