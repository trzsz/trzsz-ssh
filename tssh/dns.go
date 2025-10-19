/*
MIT License

Copyright (c) 2023-2025 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// setDNS sets the net.DefaultResolver to use the given DNS server.
func setDNS(dns string) {

	network, dns, err := resolveDnsAddress(dns)
	if err != nil {
		return

	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			debug("use custom DNS: %s://%s", network, dns)
			var d net.Dialer
			return d.DialContext(ctx, network, dns)
		},
	}

}

func resolveDnsAddress(dns string) (string, string, error) {

	var preParseDns string
	if !strings.Contains(dns, "://") {
		preParseDns = "udp://" + dns
	} else {
		preParseDns = dns
	}

	svrParse, err := url.Parse(preParseDns)
	if err != nil {
		warning("parse dns [%s] failed: %v", dns, err)
		return "", "", err

	}

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
	return network, dns, nil

}

func lookupDnsSrv(name string) (string, string, error) {
	_, addrs, err := net.LookupSRV("ssh", "tcp", name)
	if err != nil {
		return "", "", err
	}
	if len(addrs) == 0 {
		return "", "", fmt.Errorf("no srv record")
	}
	host := strings.TrimRight(addrs[0].Target, ".")
	port := addrs[0].Port
	return host, strconv.Itoa(int(port)), nil
}
