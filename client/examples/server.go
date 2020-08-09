package main

import (
	"log"
	//"io/ioutil"
	"net/http"

	"github.com/simplepki/client"
)

func main() {

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	log.Println("Getting new simplepki client")
	simplepkiClient := client.New()
	config, err := simplepkiClient.NewTLSConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: config,
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}
