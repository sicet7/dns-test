package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/miekg/dns"
)

type DnsPeer struct {
	SPKIHash   string
	ServerName string
	Ip         string
	Port       int
}

var GlobalPeers = []DnsPeer{
	{
		Ip:         "1.1.1.1",
		ServerName: "one.one.one.one",
		Port:       853,

		//echo | openssl s_client -connect 1.1.1.1:853 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
		SPKIHash: "HdDBgtnj07/NrKNmLCbg5rxK78ZehdHZ/Uoutx4iHzY=",
	},
}

// verifySPKIHash verifies the SPKI hash of the certificate
func verifySPKIHash(cert *x509.Certificate, expectedHash string) error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}
	hash := sha256.Sum256(pubKeyBytes)
	if base64.StdEncoding.EncodeToString(hash[:]) != expectedHash {
		return errors.New("SPKI hash mismatch")
	}
	fmt.Println("SPKI hash matched")
	return nil
}

// queryDNSSECOverTLS performs a DNS query over TLS and verifies the DNSSEC status
func queryDNSSECOverTLS(domain string, peer DnsPeer, qType uint16) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Net = "tcp-tls"
	c.TLSConfig = &tls.Config{
		ServerName: peer.ServerName, // Use the hostname for certificate verification
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Parse the raw certificates
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %v", err)
				}
				certs[i] = cert
			}

			// Perform SPKI pinning
			return verifySPKIHash(certs[0], peer.SPKIHash)
		},
	}

	// Set up a DNS message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qType)
	m.SetEdns0(4096, true)

	// Perform the DNS query
	r, _, err := c.Exchange(m, fmt.Sprintf("%s:%d", peer.Ip, peer.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to query DNS over TLS: %v", err)
	}

	return r, nil
}

// resolveDomain recursively resolves the domain to its final A record
func resolveDomain(domain string, peer DnsPeer) (string, error) {
	visited := make(map[string]struct{})

	for {
		if _, seen := visited[domain]; seen {
			return "", errors.New("CNAME loop detected")
		}
		visited[domain] = struct{}{}

		resp, err := queryDNSSECOverTLS(domain, peer, dns.TypeA)
		if err != nil {
			return "", err
		}

		if !resp.AuthenticatedData {
			return "", errors.New(fmt.Sprintf("failed to verify DNSSEC for domain: %s", domain))
		}

		for _, ans := range resp.Answer {
			switch v := ans.(type) {
			case *dns.A:
				return v.A.String(), nil
			case *dns.CNAME:
				domain = v.Target
			}
		}
	}
}

func doSecureLookup(domain string, peers []DnsPeer) (string, error) {
	var lastError error = nil
	for _, peer := range peers {
		ip, err := resolveDomain(domain, peer)
		if err == nil {
			return ip, nil
		}
		lastError = err
	}
	return "", lastError
}
