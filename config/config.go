package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/simplepki/pki/core/keypair"
	"github.com/spf13/viper"
)

func NewConfig(path string) (*viper.Viper, error) {
	vConfig := viper.New()
	if path != "" {
		// read in specific file
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, errors.New("Error reading in config file: " + err.Error())
		}
		configFile, err := os.Open(path)
		if err != nil {
			return nil, errors.New("Error reading in config file: " + err.Error())
		}

		switch filepath.Ext(path) {
		case ".json":
			vConfig.SetConfigType("json")
		case ".yaml", ".yml":
			vConfig.SetConfigType("yaml")
		default:
			return nil, errors.New("Error reading in config file: unknown extension (" + filepath.Ext(path) + ")")
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
	if err != nil {               // Handle errors reading the config file
		return nil, fmt.Errorf("Error reading in config file: %s \n", err.Error())
	}

	return vConfig, nil
}

func GetCAStoreType(v *viper.Viper) string {
	if v.IsSet("memory") {
		return "memory"
	}

	if v.IsSet("filesystem") {
		return "filesystem"
	}

	if v.IsSet("yubikey") {
		return "yubikey"
	}

	return "memory"
}

func ShouldOverwriteCA(v *viper.Viper) bool {
	if v.IsSet("overwrite") {
		return v.GetBool("overwrite")
	}

	return false
}

func GetKeyPairConfig(v *viper.Viper) (*keypair.KeyPairConfig, error) {
	config := &keypair.KeyPairConfig{}
	config.CommonName = getCommonName(v)
	switch GetCAStoreType(v) {
	case "memory":
		memConfig := GetInMemoryKeyPairConfig("memory", v)
		config.KeyAlgorithm = getKeyAlgorithm(v)

		config.KeyPairType = keypair.InMemory
		config.InMemoryConfig = memConfig
	case "filesystem":
		fileConfig := &keypair.FileSystemKeyPairConfig{
			KeyAlgorithm: getKeyAlgorithm(v),
		}

		if v.IsSet("filesystem.key_file") {
			fileConfig.CertFile = v.GetString("filesystem.key_file")
		}

		if v.IsSet("filesystem.cert_file") {
			fileConfig.CertFile = v.GetString("filesystem.cert_file")
		}

		if v.IsSet("filesystem.chain_file") {
			fileConfig.CertFile = v.GetString("filesystem.chain_file")
		}

		config.KeyAlgorithm = getKeyAlgorithm(v)
		config.KeyPairType = keypair.FileSystem
		config.FileSystemConfig = fileConfig
	case "yubikey":
		yubiConfig := &keypair.YubikeyKeyPairConfig{}

		config.KeyAlgorithm = getKeyAlgorithm(v)
		config.KeyPairType = keypair.Yubikey
		config.YubikeyConfig = yubiConfig
	}

	return config, nil
}

func getKeyAlgorithm(v *viper.Viper) keypair.Algorithm {
	if v.IsSet("algorithm") {
		switch v.GetString("algorithm") {
		case "ec256":
			return keypair.AlgorithmEC256
		case "ec384":
			return keypair.AlgorithmEC384
		case "rsa2048":
			return keypair.AlgorithmRSA2048
		case "rsa4096":
			return keypair.AlgorithmRSA4096
		default:
			return keypair.AlgorithmEC384
		}
	} else {
		return keypair.AlgorithmEC384
	}
}

func getCommonName(v *viper.Viper) string {
	if v.IsSet("common_name") {
		return v.GetString("common_name")
	} else {
		return ""
	}
}

func GetInMemoryKeyPairConfig(path string, v *viper.Viper) *keypair.InMemoryKeyPairConfig {
	config := &keypair.InMemoryKeyPairConfig{}
	config.KeyAlgorithm = getKeyAlgorithm(v)

	return config
}

func GetFileSystemKeyPairConfig(v *viper.Viper) *keypair.FileSystemKeyPairConfig {
	config := &keypair.FileSystemKeyPairConfig{}
	config.KeyAlgorithm = getKeyAlgorithm(v)

	if viper.IsSet("filesystem.key_file") {
		config.KeyFile = viper.GetString("filesystem.key_file")
	} else {
		config.KeyFile = "./key.pem"
	}

	if viper.IsSet("filesystem.cert_file") {
		config.KeyFile = viper.GetString("filesystem.cert_file")
	} else {
		config.KeyFile = "./cert.pem"
	}

	if viper.IsSet("filesystem.chain_file") {
		config.KeyFile = viper.GetString("filesystem.chain_file")
	} else {
		config.KeyFile = "./chain.pem"
	}
	return config
}

func GetYubikeyKeyPairConfig(path string, v *viper.Viper) *keypair.YubikeyKeyPairConfig {
	config := &keypair.YubikeyKeyPairConfig{}

	if v.IsSet(path + ".subject_name") {
		config.CertSubjectName = v.GetString(path + ".subject_name")
	}

	if v.IsSet(path + ".reset") {
		config.Reset = v.GetBool(path + ".reset")
	}

	if v.IsSet(path + ".yubikey_name") {
		name := v.GetString("")
		config.Name = &name
	}

	if v.IsSet(path + ".yubikey_serial_number") {
		num := v.GetUint32(path + ".yubikey_serial_number")
		config.Serial = &num
	}

	if v.IsSet(path + ".pin") {
		pin := v.GetString(path + ".pin")
		config.PIN = &pin
	}

	if v.IsSet(path + ".puk") {
		puk := v.GetString(path + ".puk")
		config.PUK = &puk
	}

	if v.IsSet(path + ".management_key") {
		mk := v.GetString(path + ".management_key")
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
