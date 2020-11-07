package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "simplepki",
	Short: "simplepki is the command line interface for using simplepki",
}

func Execute() error {
	return rootCmd.Execute()
}
