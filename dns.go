package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// GetWindowsDNSServer retrieves the DNS server on Windows
func GetWindowsDNSServer() (string, error) {
	output, err := exec.Command("nslookup", "example.com").Output()
	if err != nil {
		return "", fmt.Errorf("error getting DNS server: %v", err)
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Address:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("DNS server not found")
}

// GetUnixDNSServer retrieves the DNS server on Unix-like systems
func GetUnixDNSServer() (string, error) {
	// Read the resolv.conf file for DNS server addresses
	output, err := exec.Command("cat", "/etc/resolv.conf").Output()
	if err != nil {
		return "", fmt.Errorf("error getting DNS server: %v", err)
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("DNS server not found")
}

// GetDefaultDNSServer retrieves the default DNS server based on the OS
func GetDefaultDNSServer() (string, error) {
	var err error
	var dnsServer string

	switch runtime.GOOS {
	case "windows":
		dnsServer, err = GetWindowsDNSServer()
	case "linux", "darwin":
		dnsServer, err =  GetUnixDNSServer()
	default:
		dnsServer, err = "8.8.8.8", nil
	}

	if !strings.HasSuffix(dnsServer, ":53") {
		dnsServer = dnsServer + ":53"
	}

	return dnsServer, err
}
