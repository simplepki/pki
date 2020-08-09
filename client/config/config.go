package config

import (
	"log"
	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigName("simplepki")
	viper.AddConfigPath("/etc/")
	viper.AddConfigPath("$HOME/.simplepki")
	viper.AddConfigPath(".")
	
	viper.SetEnvPrefix("simplepki")
	// global
	viper.BindEnv("account")
	viper.BindEnv("endpoint")
	viper.BindEnv("token")

	// ca
	viper.BindEnv("certificate_authority")
	// inter
	viper.BindEnv("intermediate_certificate_authority")

	// cert
	viper.BindEnv("chain")
	viper.BindEnv("id")	
	viper.BindEnv("subj_alt_names")
	
	// tokens
	viper.BindEnv("token_generator")
	viper.BindEnv("token_prefix")
	viper.BindEnv("token_ttl")
}

func Load() {
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// this is ok; jut use env
		} else {
			log.Printf("Error reading config: %s\n", err.Error())
		}
	} else {
		log.Fatal(err.Error())
	}
}