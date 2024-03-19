package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
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

// Checks if the 'dig' command is available on the system
func checkDigAvailable() bool {
    _, err := exec.LookPath("dig")
    return err == nil
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
	remoteContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading remote content: %v", err)
	}

	// Read the content of the local file, if it exists
	localContent, err := ioutil.ReadFile(fingerprintsFile)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("error reading local file: %v", err)
	}

	// Compare the content of the remote and local files
	if string(remoteContent) != string(localContent) {
		// Write the fetched content to the local file
		err := ioutil.WriteFile(fingerprintsFile, remoteContent, 0644)
		if err != nil {
			return false, fmt.Errorf("error writing to local file: %v", err)
		}
		return true, nil
	}

	return false, nil
}

// Loads fingerprints from the specified file into a map
func loadFingerprints(filename string) (map[string]map[string]interface{}, error) {
    var fingerprints []map[string]interface{}
    fingerprintData, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    
    err = json.Unmarshal(fingerprintData, &fingerprints)
    if err != nil {
        return nil, err
    }

    // Map to hold fingerprints indexed by both cname and service name.
    fingerprintMap := make(map[string]map[string]interface{})
    for _, fingerprint := range fingerprints {
        // Index by cname.
        if cnames, ok := fingerprint["cname"].([]interface{}); ok {
            for _, cname := range cnames {
                fingerprintMap[strings.ToLower(cname.(string))] = fingerprint
            }
        }
        // Additionally, index by service name if available.
        if service, ok := fingerprint["service"].(string); ok {
            fingerprintMap[strings.ToLower(service)] = fingerprint
        }
    }

    return fingerprintMap, nil
}

// Extracts unique common names from the JSON data returned by crt.sh
func extractUniqueCommonNames(data []map[string]interface{}) map[string]bool {
	uniqueCommonNames := make(map[string]bool)
	for _, entry := range data {
		if cn, ok := entry["common_name"].(string); ok {
			uniqueCommonNames[cn] = true
		}
	}
	return uniqueCommonNames
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

// Writes the extracted subdomains to the specified file
func writeSubdomainsToFile(subdomains map[string]bool, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for cn := range subdomains {
		file.WriteString(cn + "\n")
	}
	return nil
}

func ifThenElse(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
}

func appendResultBasedOnVulnerability(vulnerable bool, message string) {
    if vulnerable {
        isExploitable = append(isExploitable, message)
    } else {
        notExploitable = append(notExploitable, message)
    }
}
