package main

import (
	"log"

	//"github.com/simplepki/client/tls"
	"github.com/simplepki/client"
	_ "github.com/simplepki/client/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(newCmd)
	newCmd.AddCommand(newCACmd)
	newCmd.AddCommand(newInterCmd)
	newCmd.AddCommand(newCertCmd)
	newCmd.AddCommand(newTokenCmd)

	// generic options for using the service
	newCmd.PersistentFlags().StringP("account", "a", "", "account to add certificate to")
	newCmd.PersistentFlags().StringP("endpoint", "e", "", "url to send request to")
	newCmd.PersistentFlags().StringP("token", "t", "", "token for authn/z to simple pki service")
	viper.BindPFlag("account", newCmd.PersistentFlags().Lookup("account"))
	viper.BindPFlag("endpoint", newCmd.PersistentFlags().Lookup("endpoint"))
	viper.BindPFlag("token", newCmd.PersistentFlags().Lookup("token"))

	// specific to generating a CA
	newCACmd.PersistentFlags().StringP("name", "n", "", "name of the CA to create")
	viper.BindPFlag("certificate_authority", newCACmd.PersistentFlags().Lookup("name"))

	// specific to generating an intermediate CA
	newInterCmd.PersistentFlags().StringP("name", "n", "", "name of the Intermediate CA to create")
	newInterCmd.PersistentFlags().StringP("ca-name", "c", "", "name of the CA to sign the Intermediate CA")
	viper.BindPFlag("intermediate_certificate_authority", newInterCmd.PersistentFlags().Lookup("name"))
	viper.BindPFlag("certificate_authority", newInterCmd.PersistentFlags().Lookup("ca-name"))

	// specific to generating a cert
	newCertCmd.PersistentFlags().StringP("id", "i", "", "id of certificate to request")
	newCertCmd.PersistentFlags().StringP("intermediate-chain", "c", "", "path to request certificate from")
	newCertCmd.PersistentFlags().StringArrayP("subj-alt-names", "s", []string{"localhost", "127.0.0.1"}, "subject alternative names (SANs) for cert")
	viper.BindPFlag("id", newCertCmd.PersistentFlags().Lookup("id"))
	viper.BindPFlag("chain", newCertCmd.PersistentFlags().Lookup("intermediate-chain"))
	viper.BindPFlag("subj_alt_names", newCertCmd.PersistentFlags().Lookup("subj-alt-names"))

	// specific to generating a token
	newTokenCmd.PersistentFlags().StringP("generator", "", "", "ARN of the Lambda to execute and generate a token (uses AWS credentials")
	newTokenCmd.PersistentFlags().StringP("prefix", "p", "", "glob pattern for certificate chain access permissions")
	newTokenCmd.PersistentFlags().Int64P("ttl", "", 1, "ttl in hours of the token")
	viper.BindPFlag("token_generator", newTokenCmd.PersistentFlags().Lookup("generator"))
	viper.BindPFlag("token_prefix", newTokenCmd.PersistentFlags().Lookup("prefix"))
	viper.BindPFlag("token_ttl", newTokenCmd.PersistentFlags().Lookup("ttl"))
}

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "create new certificate authorities or certificates",
}

var newCACmd = &cobra.Command{
	Use:   "certificate-authority",
	Aliases: []string{"ca"},
	Short: "generate new certificate authority",
	Run: func(cmd *cobra.Command, args []string) {
		c := client.New()
		err := c.NewCertificateAuthority()
		if err != nil {
			log.Println(err.Error())
		}
	},
}

var newInterCmd = &cobra.Command{
	Use:   "intermediate-authority",
	Aliases: []string{"intermediate","inter"},
	Short: "generate new intermediate certificate authority",
	Run: func(cmd *cobra.Command, args []string) {
		c := client.New()
		err := c.NewIntermediateCertificateAuthority()
		if err != nil {
			log.Println(err.Error())
		}
	},
}

var newCertCmd = &cobra.Command{
	Use:   "certificate",
	Aliases: []string{"cert"},
	Short: "generate new certificate",
	Run: func(cmd *cobra.Command, args []string) {
		c := client.New()
		err := c.NewCertPair()
		if err != nil {
			log.Println(err.Error)
		}
		
	},
}

var newTokenCmd = &cobra.Command {
	Use: "token",
	Short: "generate new token for client use",
	Run: func(cmd *cobra.Command, args []string) {
		c := client.New()
		token, err := c.GetToken()
		if err != nil {
			log.Println(err.Error())
		}

		log.Println(token)
	},
}

