package cli

import "github.com/spf13/cobra"

func versionCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "version",
		Short: "prints the version of ejson-kms",
	}

	cmd.RunE = func(_ *cobra.Command, args []string) error {
		cmd.Printf("ejson-kms %s (%s) built %s\n", version, sha1, builtAt)
		return nil
	}

	return cmd

}
