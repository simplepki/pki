package client

import (
	"bytes"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/spf13/viper"
	"github.com/simplepki/client/config"
	"github.com/simplepki/client/tls"
	"github.com/simplepki/core/types"

)

func New() *Client {
	config.Load()
	log.Print("account: ", viper.Get("account"))
	log.Print("id: ", viper.Get("id"))
	log.Print("chain: ", viper.Get("chain"))
	log.Print("endpoint: ", viper.Get("endpoint"))
	log.Print("ca: ", viper.Get("certificate_authority"))
	log.Print("inter: ", viper.Get("intermediate_certificate_authority"))
	log.Print("token: ", viper.Get("token"))
	return &Client{}
}

func NewWithToken() (*Client, error) {
	c := New()
	token, err := c.GetToken()
	if err != nil {
		return nil, err
	}

	c.SetToken(token)

	return c, nil
}

type Client struct {
	TLSContext *tls.TLSContext
}

func (c *Client) SetToken(token string) {
	viper.Set("token", token)
}

func (c *Client) GetToken() (string, error) {
	log.Println("NOTICE: this uses loaded AWS credentials; user must have requisite IAM priviledges")

	tokenEvent := types.CreateCredentialsEvent{
		Account: viper.GetString("account"),
		Type: "local",
		Prefix: viper.GetString("token_prefix"),
		TTL: viper.GetInt64("token_ttl") * 60 * 60,
	}

	jsonEvent, err := json.Marshal(tokenEvent)
	if err != nil {
		return "", err
	}

	lambdaInput := &lambda.InvokeInput{
		FunctionName: aws.String(viper.GetString("token_generator")),
		Payload: jsonEvent,
	}

	svc := lambda.New(session.New())
	lambdaOutput, err := svc.Invoke(lambdaInput)
	if err != nil {
		return "", err
	}

	return string(lambdaOutput.Payload), nil
}


func(c *Client) NewCertificateAuthority() error {
	log.Printf("Createing new CA with name %s\n", viper.GetString("certificate_authority"))
	caEvent := types.CreateCertificateAuthorityEvent{
		Token: viper.GetString("token"),
		CAName: viper.GetString("certificate_authority"),
		Account: viper.GetString("account"),
	}
	log.Printf("Client sending CA create event to endpoint: %s\n", viper.Get("endpoint"))
	jsonBytes, err := json.Marshal(caEvent)
	if err != nil {
		return err
	}

	caRequest, err := http.NewRequest("POST", viper.GetString("endpoint")+"/create_ca", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil
	}

	caRequest.Header.Set("Content-Type", "application/json")
	httpClient := newHTTPClient()
	log.Println("sending CA request")
	response, err := httpClient.Do(caRequest)
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Recieved code %v when creating CA", response.StatusCode))
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("Client response error: ", err.Error())
		return nil
	}

	err = errorHandler(body)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) NewIntermediateCertificateAuthority() error {
	log.Printf("Createing new Intermediate CA with name %s\n", viper.GetString("certificate_authority"))
	caEvent := types.CreateIntermediateAuthorityEvent{
		Token: viper.GetString("token"),
		CAName: viper.GetString("certificate_authority"),
		InterName: viper.GetString("intermediate_certificate_authority"),
		Account: viper.GetString("account"),
	}
	log.Printf("Client sending Intermediate CA create event to endpoint: %s\n", viper.Get("endpoint"))
	jsonBytes, err := json.Marshal(caEvent)
	if err != nil {
		return err
	}

	caRequest, err := http.NewRequest("POST", viper.GetString("endpoint")+"/create_intermediate", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil
	}

	caRequest.Header.Set("Content-Type", "application/json")
	httpClient := newHTTPClient()
	log.Println("sending CA request")
	response, err := httpClient.Do(caRequest)
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Recieved code %v when creating CA", response.StatusCode))
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("Client response error: ", err.Error())
		return nil
	}

	err = errorHandler(body)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) NewCertPair() error {
	certContext := tls.NewKeyPair(viper.GetString("account"), viper.GetString("chain"), viper.GetString("id"))
	//log.Println(string(cert.CSRRequest(viper.GetString("token"))))
	log.Println("Client sending CSR to: ", viper.GetString("endpoint"))
	certRequest, err := http.NewRequest("POST", viper.GetString("endpoint")+"/sign_csr", bytes.NewBuffer(certContext.CSRRequest(viper.GetString("token"), viper.GetStringSlice("subj_alt_names"))))
	if err != nil {
		return err
	}
	certRequest.Header.Set("Content-Type", "application/json")
	httpClient := newHTTPClient()
	log.Println("client sending CSR")
	response, err := httpClient.Do(certRequest)
	if err != nil {
		log.Println("Client.Do error: ", err.Error())
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("Client response error: ", err.Error())
		return nil
	}

	var returnedCert types.ReturnCertificateEvent
	log.Println(string(body))
	err = json.Unmarshal(body, &returnedCert)
	if err != nil {
		return err
	}

	certContext.KeyPair.ImportCertificate([]byte(returnedCert.Cert))
	chain := make([][]byte, len(returnedCert.Chain))
	for idx, chainCert := range returnedCert.Chain {
		chain[idx] = []byte(chainCert)
	}

	certContext.KeyPair.ImportCertificateChain(chain)

	log.Printf("TLS Context: %#v\n", certContext)

	c.TLSContext = certContext
	
	return nil
}

func (c *Client) NewTLSConfig() (*stdtls.Config, error) {
	if c.TLSContext == nil {
		err := c.NewCertPair()
		if err != nil {
			return nil, err
		}
	}

	certPool := x509.NewCertPool()
	for _, cert := range c.TLSContext.KeyPair.GetCertificateChain() {
		certPool.AddCert(cert)
	}


	config := &stdtls.Config{
		NextProtos:               []string{"http/1.1"},
		MinVersion:               stdtls.VersionTLS12,
		CurvePreferences:         []stdtls.CurveID{stdtls.CurveP521, stdtls.CurveP384, stdtls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			stdtls.TLS_AES_128_GCM_SHA256,
			stdtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			stdtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			stdtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			stdtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			stdtls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			stdtls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		InsecureSkipVerify:       false,
		RootCAs: certPool,
		ClientCAs: certPool,
		ClientAuth: stdtls.RequireAndVerifyClientCert,
		Certificates: []stdtls.Certificate{c.TLSContext.KeyPair.TLSCertificate()},
	}

	return config, nil
}

func newHTTPClient() *http.Client {
	c := &http.Client{
		Timeout: 1 * time.Minute,
	}

	return c
}

func errorHandler(lambdaBody []byte) error {
	var lerror types.LambdaError
	err := json.Unmarshal(lambdaBody, &lerror)
	if err != nil {
		return err
	}

	return errors.New(lerror.Message)
}

