package cli

import (
	ca "github.com/simplepki/pki/cmd/certificate_authority"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(caCmd)
	caCmd.AddCommand(ca.ShowCmd)
}

var caCmd = &cobra.Command{
	Use:     "certificate-authority",
	Aliases: []string{"ca"},
	Short:   "certificate authority actions",
}
