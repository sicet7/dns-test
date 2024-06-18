package main

import (
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	// Create a custom DNS resolver
	resolver := &customResolver{}

	// Create a custom HTTP transport that uses the custom dialer with the resolver
	transport := &http.Transport{
		DialContext:         customDialContext(resolver),
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
