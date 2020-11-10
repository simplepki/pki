package ca

import (
	"github.com/simplepki/pki/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	InitCmd.Flags().StringVarP(&configFile, "config-file", "f", "", "config file to use")
}

var InitCmd = &cobra.Command{
	Use:     "initialize",
	Aliases: []string{"init", "new"},
	Short:   "configure certificate authority",
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Debug("running certificate-authority initialize command")
		vconfig, err := config.NewConfig(configFile)
		if err != nil {
			logrus.Fatal("Error reading in config file: " + err.Error())
		}

		logrus.Infof("CA Type: %v", config.GetCAStoreType(vconfig))
		logrus.Infof("CA Overwrite: %v", config.ShouldOverwriteCA(vconfig))

		kpConfig, configErr := config.GetCAKeyPairConfig(vconfig)
		if configErr != nil {
			logrus.Errorf("Error reading CA config: %v", configErr.Error())
			return
		}

		logrus.Infof("CA Common Name: %v", kpConfig.CommonName)
	},
}
