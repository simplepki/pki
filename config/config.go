package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/simplepki/pki/core/keypair"
	"github.com/spf13/viper"
)


func NewConfig(path string) (*viper.Viper, error) {
	vConfig := viper.New()
	if path != "" {
		// read in specific file
		if _, err := os.Stat(path); os.IsNotExist(err) {
			retrun nil, errors.New("Error reading in config file: "+err.Error())
		  }
		configFile, err := os.Open(path)
		if err != nil {
			return nil, errors.New("Error reading in config file: "+err.Error())
		}

		switch filepath.Ext(path) {
		case "json":
			vConfig.SetConfigType("json")
		case "yaml","yml":
			vConfig.SetConfigType("yaml")
		default:
			return nil, errors.New("Error reading in config file: unknown extension")
		}

		vConfig.ReadConfig(configFile)
		return vConfig, nil
	}

	//read in defaults
	vConfig.SetConfigName("settings")
	vConfig.AddConfigPath("/etc/simplepki/")
	vConfig.AddConfigPath("/opt/simplepki/")
	vConfig.AddConfigPath("$HOME/.simplepki/")
	vConfig.AddConfigPath(".")

	err := vConfig.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		return nil, fmt.Errorf("Error reading in config file: %s \n", err))
	}

	return vConfig, nil
}

func IsCAEnabled(v *viper.Viper) bool {
	return v.IsSet("ca")
}

func GetCAStoreType(v *viper.Viper) string {
	if v.IsSet("ca.memory") {
		return "memory"
	}

	if v.IsSet("ca.filesystem") {
		return "filesystem"
	}

	if v.IsSet("ca.yubikey") {
		return "yubikey"
	}
	
	return "memory"
}

func ShouldOverwriteCA(v *viper.Viper) bool {
	if v.IsSet("ca.overwrite") {
		return v.GetBool("ca.overwrite")
	}

	return false
}

func GetCAKeyPairConfig(v *viper.Viper) (*keypair.KeyPairConfig, error) {
	config := &keypair.KeyPairConfig{}
	switch GetCAStoreType(v) {
	case "memory":
		memConfig := GetInMemoryKeyPairConfig("ca.memory")

		config.KeyPairType = keypair.InMemory
		config.InMemoryConfig = memConfig
	case "filesystem":
		fileConfig := &keypair.FileSystemKeyPairConfig{}

		config.KeyPairType = keypair.FileSystem
		config.FileSystemConfig = fileConfig
	case "yubikey":
		yubiConfig := &keypair.YubikeyKeyPairConfig{}

		config.KeyPairType = keypair.Yubikey
		config.YubikeyConfig = yubiConfig
	}

	return config, nil
}

func getKeyAlgorithm(path string, v *viper.Viper) keypair.Algorithm {
	if vipver.IsSet(path + ".algorithm") {
		switch viper.GetString(path + ".algorithm") {
		case "ec256":
			return keypair.AlgorithmEC256
		case "ec384":
			return keypair.AlgorithmEC384
		case "rsa2048":
			return keypair.AlgorithmRSA2048
		case "rsa4096":
			return keypair.AlgorithmRSA4096
		}
	} else {
		return keypair.AlgorithmEC384
	}
}
func GetInMemoryKeyPairConfig(path string, v *viper.Viper) *keypair.InMemoryKeyPairConfig {
	config := &keypair.InMemoryKeyPairConfig{}
	config.KeyAlgorithm = getKeyAlgorithm(path, v)
	
	return config
}

func GetFileSystemKeyPairConfig(path string) *keypair.FileSystemKeyPairConfig {
	config := &keypair.FileSystemKeyPairConfig{}

	/*if viper.IsSet(path +".algorithm") {
		switch viper.IsSet(path +".algorithm"){
		case "ec256":
			config.KeyAgorithm = keypair.AlgorithmEC256
		case "ec384":
			config.KeyAgorithm = keypair.AlgorithmEC384
		case "rsa2048":
			config.KeyAgorithm = keypair.AlgorithmRSA2048
		case "rsa4096":
			config.KeyAgorithm = keypair.AlgorithmRSA4096
		}
	}*/

	if viper.IsSet(path + ".key_file") {
		config.KeyFile = viper.GetString(path + ".key_file")
	} else {
		config.KeyFile = "./key.pem"
	}

	if viper.IsSet(path + ".cert_file") {
		config.KeyFile = viper.GetString(path + ".cert_file")
	} else {
		config.KeyFile = "./cert.pem"
	}

	if viper.IsSet(path + ".chain_file") {
		config.KeyFile = viper.GetString(path + ".chain_file")
	} else {
		config.KeyFile = "./chain.pem"
	}
	return config
}

func GetYubikeyKeyPairConfig(path string) *keypair.YubikeyKeyPairConfig {
	config := &keypair.YubikeyKeyPairConfig{}

	if viper.IsSet(path + ".subject_name") {
		config.CertSubjectName = viper.GetString(path + ".subject_name")
	}

	if viper.IsSet(path + ".reset") {
		config.Reset = viper.GetBool(path + ".reset")
	}

	if viper.IsSet(path + ".yubikey_name") {
		name := viper.GetString("")
		config.Name = &name
	}

	if viper.IsSet(path + ".yubikey_serial_number") {
		num := viper.GetUint32(path + ".yubikey_serial_number")
		config.Serial = &num
	}

	if viper.IsSet(path + ".pin") {
		pin := viper.GetString(path + ".pin")
		config.PIN = &pin
	}

	if viper.IsSet(path + ".puk") {
		puk := viper.GetString(path + ".puk")
		config.PUK = &puk
	}

	if viper.IsSet(path + ".management_key") {
		mk := viper.GetString(path + ".management_key")
		config.Base64ManagementKey = &mk
	}
	return config
}

func GetAuthProvider() (string, error) {
	if !viper.IsSet("auth_provider") {
		return "", errors.New("no auth_provider given")
	}

	return viper.GetString("auth_provider.type"), nil
}
