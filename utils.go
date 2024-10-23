package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

func printIntro() {
	color.Green("##################################\n")
	color.Green("#                                #\n")
	color.Green("#           SubSnipe             #\n")
	color.Green("#                                #\n")
	color.Green("#       By dub-flow with ❤️       #\n")
	color.Green("#                                #\n")
	color.Green("##################################\n\n")
}

// Checks if https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json has been updated. If so,
// our local copy gets updated too
func updateFingerprints() (bool, error) {
	url := "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"

	// Fetch the content of the remote file
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("error fetching remote file: %v", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the content of the remote file
	remoteContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading remote content: %v", err)
	}

	// Read the content of the local file, if it exists
	localContent, err := os.ReadFile(fingerprintsFile)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("error reading local file: %v", err)
	}

	// Compare the content of the remote and local files
	if string(remoteContent) != string(localContent) {
		// Write the fetched content to the local file
		err := os.WriteFile(fingerprintsFile, remoteContent, 0644)
		if err != nil {
			return false, fmt.Errorf("error writing to local file: %v", err)
		}
		return true, nil
	}

	return false, nil
}

// Loads fingerprints from the specified file into a map
func loadFingerprints() (map[string]map[string]interface{}, error) {
	var fingerprints []map[string]interface{}
	err := json.Unmarshal(embeddedFingerprintsFile, &fingerprints)
	if err != nil {
		return nil, err
	}

	// Map to hold fingerprints indexed by both cname and service name.
	fingerprintMap := make(map[string]map[string]interface{})
	for _, fingerprint := range fingerprints {
		// Index by cname
		if cnames, ok := fingerprint["cname"].([]interface{}); ok {
			for _, cname := range cnames {
				fingerprintMap[strings.ToLower(cname.(string))] = fingerprint
			}
		}
		// Additionally, index by service name if available
		if service, ok := fingerprint["service"].(string); ok {
			fingerprintMap[strings.ToLower(service)] = fingerprint
		}
	}

	return fingerprintMap, nil
}

// Extracts unique common names from the JSON data returned by crt.sh
func extractUniqueCommonNames(data []map[string]interface{}) []string {
	uniqueCommonNames := make(map[string]struct{}) // Use struct for uniqueness
	for _, entry := range data {
		if cn, ok := entry["common_name"].(string); ok {
			uniqueCommonNames[cn] = struct{}{} // Store keys as empty structs for uniqueness
		}
	}

	// Convert map keys to a slice
	domains := make([]string, 0, len(uniqueCommonNames))
	for cn := range uniqueCommonNames {
		domains = append(domains, cn)
	}
	return domains
}

// Function to read subdomains from a file
func readSubdomainsFile(subdomainsFile string) ([]string, error) {
	if _, err := os.Stat(subdomainsFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("the specified file with subdomains does not exist: %s", subdomainsFile)
	}

	fileContent, err := os.ReadFile(subdomainsFile)
	if err != nil {
		return nil, fmt.Errorf("error reading the subdomains file: %s", err)
	}

	// Split the file content by newlines to create a list of subdomains
	subdomains := strings.Split(string(fileContent), "\n")

	// Create a slice to hold only the non-empty subdomains
	var validSubdomains []string

	// Iterate through the subdomains and trim any whitespace
	for _, subdomain := range subdomains {
		trimmedSubdomain := strings.TrimSpace(subdomain)
		if len(trimmedSubdomain) > 0 { // check if the subdomain is non-empty
			validSubdomains = append(validSubdomains, trimmedSubdomain)
		}
	}

	return validSubdomains, nil
}

// Extracts the second-level domain (SLD) from a given domain name, e.g., 'ngrok' from 'blablub.ngrok.com.'
func extractServiceName(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 3 { // Example: blablub.ngrok.com.
		return parts[len(parts)-3] // Returns 'ngrok'
	}
	return ""
}

// Check if the extracted SLD matches any service marked as vulnerable or safe in fingerprints.json
func isServiceVulnerable(sld string, fingerprints map[string]map[string]interface{}) (bool, bool, string, string, bool) {
	for _, fingerprint := range fingerprints {
		service, ok := fingerprint["service"].(string)
		if ok && strings.EqualFold(service, sld) {
			fingerprintText := fingerprint["fingerprint"].(string)
			hasNXDOMAINFlag := fingerprint["nxdomain"].(bool)

			return true, fingerprint["vulnerable"].(bool), service, fingerprintText, hasNXDOMAINFlag
		}
	}
	return false, false, "", "", false
}

// Searches for a CNAME in the fingerprints and checks its vulnerability status.
func isVulnerableCNAME(cname string, fingerprints map[string]map[string]interface{}) (bool, bool, string, bool) {
	// Trim the trailing dot from the cname if present
	cname = strings.TrimSuffix(cname, ".")

	for _, fingerprint := range fingerprints {
		cnameList := fingerprint["cname"].([]interface{})
		for _, c := range cnameList {
			pattern := c.(string)
			if strings.HasSuffix(cname, pattern) {
				fingerprintText := fingerprint["fingerprint"].(string)
				hasNXDOMAINFlag := fingerprint["nxdomain"].(bool)

				return true, fingerprint["vulnerable"].(bool), fingerprintText, hasNXDOMAINFlag
			}
		}
	}
	return false, false, "", false // CNAME not found in fingerprints
}

func ifThenElse(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
}

func appendResultBasedOnVulnerability(vulnerable bool, message string) {
	if vulnerable {
		couldBeExploitable = append(couldBeExploitable, message)
	} else {
		notExploitable = append(notExploitable, message)
	}
}

// Helper function to extract subdomain from the result strings
func extractSubdomain(item string) string {
	return strings.Split(item, " ")[2]
}

// Helper function to extract CNAME from the result strings
func extractCNAME(item string) string {
	return strings.Split(item, " ")[4]
}

// Helper function to extract the status from the results string
func extractStatus(item string) string {
	if index := strings.Index(item, "("); index != -1 {
		return item[index:] // Return everything from '(' onward
	}
	return "" // Return an empty string if '(' is not found
}
