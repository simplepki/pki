package main

import (
	cli "github.com/simplepki/pki/cmd"
	"github.com/sirupsen/logrus"
)

func main() {
	if err := cli.Execute(); err != nil {
		logrus.Fatalf("simple pki command failed: %v\n", err.Error())
	}
}
