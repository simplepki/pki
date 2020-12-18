package ca

import (
	"github.com/simplepki/pki/config"
	"github.com/simplepki/pki/core/keypair"
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
		kpconfig, err := config.GetKeyPairConfig(vconfig)
		if err != nil {
			logrus.Fatal("Error getting keypair config: " + err.Error())
		}

		initKP, err := keypair.NewKeyPair(kpconfig)
		if err != nil {
			logrus.Fatal("Error initializing keypair: " + err.Error())
		}

		keypair.SelfSignKeyPair(initKP, kpconfig.CommonName, []string{}, true)
		logrus.Infof("kp: %#v", initKP)

		if cError := initKP.Close(); cError != nil {
			logrus.Fatal(err.Error())
		}
	},
}
