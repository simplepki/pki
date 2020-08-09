package main

import (
	"bytes"
	"log"
	//"io/ioutil"
	"net/http"

	"github.com/simplepki/client"
)

func main() {

	log.Println("Getting new simplepki client")
	simplepkiClient := client.New()
	config, err := simplepkiClient.NewTLSConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	transport := http.Transport{
		TLSClientConfig: config,
	}

	httpsClient := &http.Client{
		Transport: &transport,
	}

	emptyRequest, err := http.NewRequest("GET", "https://localhost:8443/", bytes.NewBuffer([]byte{}))
	if err != nil {
		log.Fatal(err.Error())
	}

	resp, err := httpsClient.Do(emptyRequest)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Printf("response recieved:\n\t%#v", resp)
}
