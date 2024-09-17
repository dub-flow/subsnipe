package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// cnameResult stores the result of a CNAME query for a domain
type cnameResult struct {
	domain string
	cname  string
	err    error
}

//go:embed fingerprints/can-i-take-over-xyz_fingerprints.json
var embeddedFingerprintsFile []byte

var (
	outputFileName        string = "output.md"
	domain                string
	threads               int
	subdomainsFile        string
	skipUpdateCheck       bool
	isExploitable         []string
	notExploitable        []string
	unknownExploitability []string
	fingerprintsFile      = filepath.Join("fingerprints", "can-i-take-over-xyz_fingerprints.json")
	RUNNING_ENVIRONMENT   string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "subsnipe [flags]",
		Short: "SubSnipe identifies potentially take-over-able subdomains",
		Example: `./subsnipe -d test.com
./subsnipe -d test.com --threads 50
./subsnipe -f subdomains.txt --skip-update-check `,
		Run: run,
	}

	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "The domain to query for subdomains")
	rootCmd.Flags().StringVarP(&subdomainsFile, "subdomains", "f", "", "Path to the file containing subdomains to query (subdomains are separated by new lines)")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 30, "Number of concurrent threads for CNAME checks")
	rootCmd.Flags().BoolVarP(&skipUpdateCheck, "skip-update-check", "u", false, "Skip update check")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing subSnipe: %s", err)
	}
}

func run(cmd *cobra.Command, args []string) {
	printIntro()
	printAppVersion()

	if !skipUpdateCheck {
		// Check if the AppVersion was already set during compilation - otherwise manually get it from `./VERSION`
		NotifyOfUpdates()
	}

	// Check if either 'domain' or 'subdomainsFile' were provided
	if (domain == "" && subdomainsFile == "") || (domain != "" && subdomainsFile != "") {
		log.Fatalf("Please either provide a domain (-d <domain>) or a file with subdomains (-f <filename>)")
	}

	if RUNNING_ENVIRONMENT != "" {
		log.Info("The RUNNING_ENVIRONMENT is: ", RUNNING_ENVIRONMENT)
	}

	// if the app runs inside a docker container, the output has to be written into `./output/output.md`, because
	// we will mount the CWD inside the container into `./output/`
	if RUNNING_ENVIRONMENT == "docker" {
		outputFileName = filepath.Join("output", outputFileName)
	}

	// if we neither run the compiled binary nor the docker image, we can presume that we run the Go code manually.
	// Thus, it's a good moment to check if the fingerprints file updated and apply these updates (if there are any)
	if RUNNING_ENVIRONMENT == "" {
		log.Info("RUNNING_ENVIRONMENT is not set, thus we assume the tool is run directly via 'go run .'")

		// Update fingerprints if running environment is not set
		if updated, err := updateFingerprints(); err != nil {
			log.Error("Error updating fingerprints: ", err)
		} else if updated {
			log.Info("Fingerprints updated")
		} else {
			log.Info("Fingerprints are already up to date")
		}
	}

	var subdomainsFilePath string
	// if the 'subdomainsFile' flag was provided
	if subdomainsFile != "" {
		// Check if the subdomains file exists
		if _, err := os.Stat(subdomainsFile); os.IsNotExist(err) {
			// If the file does not exist, log an error and exit
			log.Fatalf("The specified file with subdomains does not exist: %s", subdomainsFile)
		}
		// If the file exists, use its path directly
		subdomainsFilePath = subdomainsFile
	} else if domain != "" {
		// Query crt.sh if a domain is provided
		queryCRTSH()
		subdomainsFilePath = "crt-subdomains.txt"
	}

	log.Info("Checking subdomains for: ", domain)

	checkCNAMEs(subdomainsFilePath)
}

// Queries crt.sh for subdomains of the given domain and writes unique common names to a file
func queryCRTSH() {
	log.Info("Querying crt.sh for subdomains... (may take a moment)")

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		log.Error("Error querying crt.sh: ", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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

	subdomainsFilePath := "crt-subdomains.txt"
	if err := writeSubdomainsToFile(uniqueCommonNames, subdomainsFilePath); err != nil {
		log.Error("Error writing to file: ", err)
		return
	}

	log.Info("Unique common names have been extracted to ", subdomainsFilePath)
}

// Reads subdomains from a file and queries for their CNAME records concurrently
func checkCNAMEs(subdomainsFilePath string) {
	log.Info("Querying CNAME records for subdomains...")

	subdomainsFile, err := os.Open(subdomainsFilePath)
	if err != nil {
		log.Error("Error opening file: ", err)
		return
	}
	defer subdomainsFile.Close()

	scanner := bufio.NewScanner(subdomainsFile)
	var wg sync.WaitGroup
	results := make(chan cnameResult, 100) // Buffer may be adjusted based on expected concurrency
	sem := make(chan struct{}, threads)    // Control concurrency with a semaphore

	fingerprints, err := loadFingerprints()
	if err != nil {
		log.Fatalf("Error loading fingerprints: %v", err)
	}

	// Launch a goroutine to process results concurrently
	go func() {
		for result := range results {
			processCNAMEResult(result, fingerprints)
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
	cname, err := net.LookupCNAME(domain)
	switch {
	case err != nil:
		results <- cnameResult{domain: domain, err: fmt.Errorf("error obtaining CNAME records: %w", err)}
	case cname == domain+"." || cname == "": // net.LookupCNAME formats domain with the dot at the end, hence the first condition.
		results <- cnameResult{domain: domain, err: fmt.Errorf("no CNAME records found")}
	default:
		// Log the found CNAME
		log.Infof("CNAME found for %s is: %s", domain, strings.TrimSpace(cname))
		results <- cnameResult{domain: domain, cname: strings.TrimSpace(cname)}
	}
}

// Writes the sorted CNAME query results to an output markdown file with categorization based on exploitability
func writeResults() {
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Writing Could Be Exploitable section
	if len(isExploitable) > 0 {
		outputFile.WriteString("### Could Be Exploitable\n\n")
		for _, item := range isExploitable {
			outputFile.WriteString("- " + item + "\n")
		}
		outputFile.WriteString("\n")
	}

	// Writing Not Exploitable section
	if len(notExploitable) > 0 {
		outputFile.WriteString("### Not Exploitable\n\n")
		for _, item := range notExploitable {
			outputFile.WriteString("- " + item + "\n")
		}
		outputFile.WriteString("\n")
	}

	// Writing Exploitability Unknown section
	if len(unknownExploitability) > 0 {
		outputFile.WriteString("### Exploitability Unknown\n\n")
		for _, item := range unknownExploitability {
			outputFile.WriteString("- " + item + "\n")
		}
	}

	log.Println("Results have been written to", outputFileName)
}

// Processes each CNAME query result, checking against fingerprints and service names
func processCNAMEResult(result cnameResult, fingerprints map[string]map[string]interface{}) {
	if result.err != nil || result.cname == "" {
		notFoundMsg := fmt.Sprintf("No CNAME record found for: %s", result.domain)
		log.Warnf(notFoundMsg)
		return
	}

	// Check our fingerprints if the CNAME is known to be vulnerable to takeover
	directMatch, vulnerable, fingerprintText, hasNXDOMAINFlag := isVulnerableCNAME(result.cname, fingerprints)

	if directMatch {
		// If the TLD of the queried CNAME exists in our fingerprints and it flagged as 'vulnerable: true', we check for takeover
		if checkTakeover(result.cname, fingerprintText, hasNXDOMAINFlag) && vulnerable {
			log.Infof("+++ It's likely possible to takeover CNAME: %s +++", result.cname)
			serviceMsg := fmt.Sprintf("CNAME for %s is: %s (found matching fingerprint '%s') -> `Takeover Likely Possible!`", result.domain, result.cname, ifThenElse(vulnerable, "vulnerable", "safe"))
			appendResultBasedOnVulnerability(vulnerable, serviceMsg)
		} else {
			foundMsg := fmt.Sprintf("CNAME for %s is: %s (found matching fingerprint - %s)", result.domain, result.cname, ifThenElse(vulnerable, "vulnerable", "safe"))
			appendResultBasedOnVulnerability(vulnerable, foundMsg)
		}
	} else {
		// Handle the case where the service might be identified by its second-level domain in the fingerprints
		sld := extractServiceName(result.cname)
		if serviceMatch, vulnerable, service, fingerprintText, hasNXDOMAINFlag := isServiceVulnerable(sld, fingerprints); serviceMatch {
			// If we could potentially fingerprint the service, and it's flagged as 'vulnerable: true', we check for takeover
			if checkTakeover(result.cname, fingerprintText, hasNXDOMAINFlag) && vulnerable {
				log.Infof("+++ It's likely possible to takeover CNAME: %s +++", result.cname)
				serviceMsg := fmt.Sprintf("CNAME for %s is: %s (found potentially matching service '%s' - %s) -> Takeover Likely Possible!", result.domain, result.cname, service, ifThenElse(vulnerable, "vulnerable", "safe"))
				appendResultBasedOnVulnerability(vulnerable, serviceMsg)
			} else {
				serviceMsg := fmt.Sprintf("CNAME for %s is: %s (found potentially matching service '%s' - %s)", result.domain, result.cname, service, ifThenElse(vulnerable, "vulnerable", "safe"))
				appendResultBasedOnVulnerability(vulnerable, serviceMsg)
			}
		} else {
			unknownMsg := fmt.Sprintf("CNAME for %s is: %s", result.domain, result.cname)
			unknownExploitability = append(unknownExploitability, unknownMsg)
		}
	}
}

// Checks if the domain pointed by the CNAME is take-over-able
func checkTakeover(cname string, fingerprintText string, hasNXDOMAINFlag bool) bool {
	if hasNXDOMAINFlag {
		return checkTakeoverDNS(cname)
	} else {
		return checkTakeoverHTTP(cname, fingerprintText)
	}
}

// Checks if the domain pointed by the CNAME is take-over-able by performing a DNS query
func checkTakeoverDNS(cname string) bool {
	log.Info("Checking for NXDOMAIN for CNAME: ", cname)

	_, err := net.LookupHost(cname)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			log.Info("DNS_PROBE_FINISHED_NXDOMAIN error occurred for CNAME: ", cname)
			return true
		}

		log.Errorf("Other error occurred for CNAME %s: %s", cname, err)
		return false
	}

	log.Infof("CNAME %s is resolvable", cname)

	return false
}

func checkTakeoverHTTP(cname string, fingerprintText string) bool {
	url := "http://" + cname
	log.Info("Checking for fingerprint test in HTTP response for CNAME: ", cname)

	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("Error making HTTP request to %s: %v", url, err)
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body from %s: %v", url, err)
		return false
	}

	log.Infof("Can fingerprint %s to be takeover-able", cname)

	// Check if the response body matches the fingerprint
	return strings.Contains(string(body), fingerprintText)
}
