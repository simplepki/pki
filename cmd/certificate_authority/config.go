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

		logrus.Infof("CA Type: %v", config.GetCAStoreType())
		logrus.Infof("CA Overwrite: %v", config.ShouldOverwriteCA())

		kpConfig, configErr := config.GetCAKeyPairConfig()
		if configErr != nil {
			logrus.Errorf("Error reading CA config: %v", configErr.Error())
			return
		}

		logrus.Infof("CA Common Name: %v", kpConfig.CommonName)
	},
}
