package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
)

var cert string = "/etc/ssl/server.pem"
var key string = "/etc/ssl/server.key"

func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":8080"
}

func createServerTLS() {
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("Unable to generate server TLS self-signed private key during intialization: " + err.Error())
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
	}
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         hostname,
			Organization:       []string{"CyberArk"},
			OrganizationalUnit: []string{"PKIService"},
		},
	}
	selfCert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &newKey.PublicKey, newKey)
	if err != nil {
		log.Fatal("Unable to generate TLS self-signed certificate: " + err.Error())
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfCert})
	pemPrivKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(newKey)})
	certFile, err := os.Create(cert)
	if err != nil {
		log.Fatal("Error creating server TLS self-signed certificate file: " + err.Error())
	}
	_, err = certFile.Write(pemCert)
	if err != nil {
		log.Fatal("Error writing to server TLS self-signed certificate file: " + err.Error())
	}
	keyFile, err := os.Create(key)
	if err != nil {
		log.Fatal("Error creating server private key file: " + err.Error())
	}
	_, err = keyFile.Write(pemPrivKey)
	if err != nil {
		log.Fatal("Error writing to server private key file: " + err.Error())
	}
}

func main() {
	log.Printf("Server started")

	router := NewRouter()
	port := getPort()

	createServerTLS()
	log.Fatal(http.ListenAndServeTLS(port, cert, key, router))
}
