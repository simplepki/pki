package ca

import (
	"github.com/simplepki/pki/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var ShowCmd = &cobra.Command{
	Use:     "show-config",
	Aliases: []string{"show", "config"},
	Short:   "show current CA configurations",
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Debug("running certificate-authority show-config command")
		if !config.IsCAEnabled() {
			logrus.Info("there is no current CA configuration")
		}
	},
}
