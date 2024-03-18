package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/fatih/color"
)

// cnameResult stores the result of a CNAME query for a domain
type cnameResult struct {
	domain string
	cname  string
	err    error
}

var (
	found    []string
	notFound []string
)

var fingerprintsFile string = "./fingerprints/can-i-take-over-xyz_fingerprints.json"
var outputFile string = "output.md"

func main() {
	// Check for help request
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg == "--help" {
			printHelp()
			return
		}
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <domain>")
		os.Exit(1)
	}

	printIntro()

	// Check if the AppVersion was already set during compilation - otherwise manually get it from `./VERSION`
	CheckAppVersion()
	color.Yellow("Current version: %s\n\n", AppVersion)

	// check if a later version of this tool exists
	NotifyOfUpdates()

	// Check if https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/fingerprints.json differs from the local copy in
	// ./fingerprints/can-i-take-over-xyz_fingerprints.json (i.e., has been updated). If so, update our local copy
	log.Info("Checking for new fingerprints (this tool uses https://github.com/EdOverflow/can-i-take-over-xyz to determine subdomains that can be taken over)")
	updated, err := updateFingerprints()
	if err != nil {
		log.Error("Error updating fingerprints:", err)
		return
	}
	if updated {
		log.Info("Fingerprints updated")
	} else {
		log.Info("Fingerprints are already up to date")
	}

	domain := os.Args[1]
	log.Info("Checking subdomains for: ", domain)

	queryCRTSH(domain)
}

func printHelp() {
	fmt.Println("SubSnipe Help")
	fmt.Println("Usage: subsnipe <domain>")
	fmt.Println("Example: ./subsnipe example.com")
	fmt.Println("\nOptions:")
	fmt.Println("--help\t\tShow this help message")
	fmt.Println("\nSubSnipe queries for subdomains and checks their CNAME records to identify potentially take-over-able subdomains based on known services' fingerprints.")
}

func printIntro() {
	color.Green("##################################\n")
	color.Green("#                                #\n")
	color.Green("#           SubSnipe             #\n")
	color.Green("#                                #\n")
	color.Green("#       By dub-flow with ❤️       #\n")
	color.Green("#                                #\n")
	color.Green("##################################\n\n")
}

// Queries crt.sh for subdomains of the given domain and writes unique common names to a file
func queryCRTSH(domain string) {
	log.Info("Querying crt.sh for subdomains... (may take a moment)")

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		log.Error("Error querying crt.sh: ", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error reading response body: ", err)
		return
	}

	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Error("Error unmarshaling JSON: ", err)
		return
	}

	uniqueCommonNames := extractUniqueCommonNames(data)

	subdomainsFile := "crt-subdomains.txt"
	if err := writeSubdomainsToFile(uniqueCommonNames, subdomainsFile); err != nil {
		log.Error("Error writing to file: ", err)
		return
	}

	log.Info("Unique common names have been extracted to ", subdomainsFile)
	checkCNAMEs(subdomainsFile)
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

// Reads subdomains from a file and queries for their CNAME records concurrently
func checkCNAMEs(fileName string) {
	log.Info("Querying CNAME records for subdomains...")

	file, err := os.Open(fileName)
	if err != nil {
		log.Error("Error opening file: ", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup
	results := make(chan cnameResult, 100) // Buffer may be adjusted based on expected concurrency

	maxConcurrency := 20
	sem := make(chan struct{}, maxConcurrency) // Control concurrency with a semaphore

	// Launch a goroutine to process results concurrently
	go func() {
		for result := range results {
			if result.err != nil || result.cname == "" {
				notFoundMsg := fmt.Sprintf("No CNAME record found for: %s", result.domain)
				log.Warnf(notFoundMsg)
				notFound = append(notFound, notFoundMsg)
			} else {
				foundMsg := fmt.Sprintf("CNAME for %s is: %s", result.domain, result.cname)
				log.Infof(foundMsg)
				found = append(found, foundMsg)
			}
		}
	}()

	for scanner.Scan() {
		domain := scanner.Text()
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		// Launch a goroutine for each CNAME query
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore
			queryAndSendCNAME(domain, results)
		}(domain)
	}

	if err := scanner.Err(); err != nil {
		log.Error("Error reading from file: ", err)
		return
	}

	// Wait for all queries to finish
	wg.Wait()

	// Close the results channel after all queries are complete
	close(results)

	// Write results after processing
	writeResults()
}

// Performs a CNAME query for a given domain and sends the result to the results channel
func queryAndSendCNAME(domain string, results chan<- cnameResult) {
	cname, err := exec.Command("dig", "+short", "CNAME", domain).Output()
	if err != nil || len(cname) == 0 {
		results <- cnameResult{domain: domain, err: fmt.Errorf("no CNAME record found or dig command failed")}
		return
	}
	results <- cnameResult{domain: domain, cname: strings.TrimSpace(string(cname))}
}

// Processes CNAME query results from the results channel, sorting them into found and not found
func processResults(results <-chan cnameResult) {
	for result := range results {
		if result.err != nil || result.cname == "" {
			notFoundMsg := fmt.Sprintf("No CNAME record found for: %s", result.domain)
			log.Warnf(notFoundMsg)
			notFound = append(notFound, notFoundMsg)
		} else {
			foundMsg := fmt.Sprintf("CNAME for %s is: %s", result.domain, result.cname)
			log.Infof(foundMsg)
			found = append(found, foundMsg)
		}
	}

	log.Info("... Finished querying CNAMEs")
}

// Writes the sorted CNAME query results to an output markdown file with categorization based on exploitability
func writeResults() {
    fingerprints, err := loadFingerprints(fingerprintsFile)
    if err != nil {
        log.Fatalf("Error loading fingerprints: %v", err)
    }

    outputFile, err := os.Create(outputFile)
    if err != nil {
        log.Fatalf("Error creating output file: %v", err)
    }
    defer outputFile.Close()

    var isExploitable, notExploitable, unknownExploitability []string

    for _, f := range found {
        cname := extractCNAME(f)
        matched, vulnerable := isVulnerableCNAME(cname, fingerprints)

        if matched {
            if vulnerable {
                isExploitable = append(isExploitable, f+" (found matching fingerprint - vulnerable)")
            } else {
                notExploitable = append(notExploitable, f+" (found matching fingerprint - safe)")
            }
        } else {
            unknownExploitability = append(unknownExploitability, f)
        }
    }

    if len(isExploitable) > 0 {
        outputFile.WriteString("### Is Exploitable\n\n")
        for _, item := range isExploitable {
            outputFile.WriteString("- " + item + "\n")
        }
        outputFile.WriteString("\n")
    }

    if len(notExploitable) > 0 {
        outputFile.WriteString("### Not Exploitable\n\n")
        for _, item := range notExploitable {
            outputFile.WriteString("- " + item + "\n")
        }
        outputFile.WriteString("\n")
    }

    if len(unknownExploitability) > 0 {
        outputFile.WriteString("### Exploitability Unknown\n\n")
        for _, item := range unknownExploitability {
            outputFile.WriteString("- " + item + "\n")
        }
    }

    log.Println("Results have been written to output.md")
}

// Attempts to extract the top-level domain from a given domain name
func extractTLD(domain string) string {
    parts := strings.Split(domain, ".")
    if len(parts) >= 2 {
        // Return the last two parts of the domain as the TLD
        return parts[len(parts)-2] + "." + parts[len(parts)-1]
    }
    return domain // Return the original domain if it doesn't follow expected structure
}

// Searches for a CNAME in the fingerprints and checks its vulnerability status.
func isVulnerableCNAME(cname string, fingerprints map[string]map[string]interface{}) (bool, bool) {
    // Trim the trailing dot from the cname if present
    cname = strings.TrimSuffix(cname, ".")
    
    for _, fingerprint := range fingerprints {
        cnameList := fingerprint["cname"].([]interface{})
        for _, c := range cnameList {
            pattern := c.(string)
            if strings.HasSuffix(cname, pattern) {
                return true, fingerprint["vulnerable"].(bool)
            }
        }
    }
    return false, false // CNAME not found in fingerprints
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

// Extracts CNAME from the result string
func extractCNAME(result string) string {
	parts := strings.Split(result, "is:")
	if len(parts) > 1 {
		return strings.TrimSpace(parts[1])
	}
	return ""
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

    // Map to hold the domain (or pattern) and its fingerprint data
    fingerprintMap := make(map[string]map[string]interface{})
    for _, fingerprint := range fingerprints {
        for _, cname := range fingerprint["cname"].([]interface{}) {
            // Assuming the structure allows direct mapping like this
            fingerprintMap[cname.(string)] = fingerprint
        }
    }

    return fingerprintMap, nil
}
