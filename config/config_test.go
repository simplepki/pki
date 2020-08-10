package config

import (
	"testing"
)

func TestCASet(t *testing.T) {

	if !IsCAEnabled() {
		t.Fatal("ca is enabled")
	}
}
