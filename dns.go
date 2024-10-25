package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Uses the output of the 'nslookup' command to determine the default DNS server
func GetDefaultDNSServerNSLOOKUP() (string, error) {
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

// GetDefaultDNSServer retrieves the default DNS server based on the OS
func GetDefaultDNSServer() (string, error) {
	switch runtime.GOOS {
	case "windows", "linux", "darwin":
		return GetDefaultDNSServerNSLOOKUP()
	default:
		return "8.8.8.8", nil
	}
}
