package tssh

import (
	"context"
	"net"
	"net/url"
	"strings"
)

// SetDNS sets the net.DefaultResolver to use the given DNS server.
func SetDNS(dns string) {
	if !strings.Contains(dns, "://") {
		dns = "udp://" + dns
	}

	svrParse, _ := url.Parse(dns)

	var network string
	switch strings.ToLower(svrParse.Scheme) {
	case "tcp":
		network = "tcp"
	default:
		network = "udp"
	}

	host, port, err := net.SplitHostPort(svrParse.Host)
	if err != nil {
		// If no port is specified, use default port 53
		host = svrParse.Host
		port = "53"
	}

	dns = net.JoinHostPort(host, port)

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			debug("use custom DNS: %s", dns)
			var d net.Dialer
			return d.DialContext(ctx, network, dns)
		},
	}
}
