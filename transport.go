package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// customResolver resolves DNS queries using DNS over TLS with DNSSEC validation
type customResolver struct{}

func (r *customResolver) Resolve(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	ipStr, err := doSecureLookup(host, GlobalPeers)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	return []net.IPAddr{{IP: ip}}, nil
}

func customDialContext(resolver *customResolver) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		addrs, err := resolver.Resolve(ctx, network, host)
		if err != nil {
			return nil, err
		}

		if len(addrs) == 0 {
			return nil, fmt.Errorf("no addresses found for host %s", host)
		}

		dialer := &net.Dialer{
			Timeout: 30 * time.Second,
		}

		return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].IP.String(), port))
	}
}
