package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"time"
)

type CloudflareConfig struct {
	Key    string `yaml:"cf_key"`
	User   string `yaml:"cf_user"`
	Zone   string `yaml:"cf_zone"`
	Target string `yaml:"cf_target"`
	Ttl    int    `yaml:"cf_ttl"`
}

//go:embed cacert.pem
var caCertPEM []byte

//go:embed config.yml
var cfConfig []byte

func loadCACertificates() (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		return nil, errors.New("failed to append CA certificates")
	}
	return certPool, nil
}

func main() {
	var config CloudflareConfig
	decoder := yaml.NewDecoder(bytes.NewBuffer(cfConfig))
	if cfgErr := decoder.Decode(&config); cfgErr != nil {
		log.Fatalf("failed to load config: %v\n", cfgErr)
	}

	// Load CA certificates from embedded PEM
	certPool, err := loadCACertificates()
	if err != nil {
		log.Fatalf("Error loading CA certificates: %v\n", err)
	}

	// Create a custom DNS resolver
	resolver := &customResolver{}

	// Create a custom HTTP transport that uses the custom dialer with the resolver
	transport := &http.Transport{
		DialContext: customDialContext(resolver),
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
	}

	site := "https://sicet7.com"

	// Testing the new HTTP client with the custom DNS resolver.
	resp, err := client.Get(site)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(len(string(body)))
}
