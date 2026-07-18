/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

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
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/trzsz/iterm2"
	"golang.org/x/sys/windows"
)

func isRemoteSshEnv(pid int) bool {
	for range 1000 {
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return false
		}
		defer windows.CloseHandle(handle)

		var path [windows.MAX_PATH]uint16
		var pathLen uint32 = uint32(len(path))
		if err := windows.QueryFullProcessImageName(handle, 0, &path[0], &pathLen); err != nil {
			return false
		}

		name := filepath.Base(windows.UTF16ToString(path[:pathLen]))
		if name == "sshd.exe" || name == "tsshd.exe" {
			return true
		}

		pbi := windows.PROCESS_BASIC_INFORMATION{}
		if err := windows.NtQueryInformationProcess(handle, windows.ProcessBasicInformation,
			unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil {
			return false
		}
		pid = int(pbi.InheritedFromUniqueProcessId)
	}
	return false
}

func isNoGUI() bool {
	return isRemoteSshEnv(os.Getppid())
}

func getIterm2Session() *iterm2.Session {
	return nil
}

func windowsDnsServers() []dnsServer {
	buf, err := getAdapterAddresses()
	if err != nil {
		debug("get dns servers failed: %v", err)
		return nil
	}
	if len(buf) == 0 {
		return nil
	}

	var servers []dnsServer
	seen := make(map[string]bool)

	for adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}

		for dns := adapter.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			sockaddr, err := dns.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}

			switch sockaddr := sockaddr.(type) {
			case *syscall.SockaddrInet4:
				servers = appendDnsServer(servers, seen, netip.AddrFrom4(sockaddr.Addr).String())

			case *syscall.SockaddrInet6:
				// Ignore deprecated site-local anycast DNS servers.
				// Windows may populate these addresses when no IPv6 DNS server is configured.
				// See RFC 3879: https://datatracker.ietf.org/doc/html/rfc3879
				if sockaddr.Addr[0] == 0xfe && sockaddr.Addr[1] == 0xc0 {
					continue
				}

				ip := netip.AddrFrom16(sockaddr.Addr)
				if sockaddr.ZoneId != 0 {
					ip = ip.WithZone(strconv.FormatUint(uint64(sockaddr.ZoneId), 10))
				}

				servers = appendDnsServer(servers, seen, ip.String())
			}
		}
	}

	return servers
}

func getAdapterAddresses() ([]byte, error) {
	size := uint32(15 * 1024)

	for {
		buf := make([]byte, size)

		err := windows.GetAdaptersAddresses(
			syscall.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_FRIENDLY_NAME,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])),
			&size,
		)

		if err == nil {
			if size == 0 {
				return nil, nil
			}
			return buf, nil
		}

		if errno, ok := err.(syscall.Errno); !ok || errno != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, os.NewSyscallError("GetAdaptersAddresses", err)
		}

		if size <= uint32(len(buf)) {
			return nil, os.NewSyscallError("GetAdaptersAddresses", err)
		}
	}
}
