package server

import (
	"github.com/simplepki/pki/config"
)

func InitializeCA() error {
	if config.IsCAEnabled() && config.ShouldOverwriteCA() {
		//new ca

	} else {
		// error if ca is not whats expected
	}

	return nil
}
