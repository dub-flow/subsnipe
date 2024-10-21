package main

import (
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
	outputFileName        string
	domain                string
	threads               int
	subdomainsFile        string
	skipUpdateCheck       bool
	couldBeExploitable    []string
	notExploitable        []string
	unknownExploitability []string
	fingerprintsFile      = filepath.Join("fingerprints", "can-i-take-over-xyz_fingerprints.json")
	RUNNING_ENVIRONMENT   string
	outputFormat          string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "subsnipe [flags]",
		Short: "SubSnipe identifies potentially take-over-able subdomains",
		Example: `./subsnipe -d test.com
./subsnipe -d test.com --threads 50 --output my_output.md
./subsnipe -s subdomains.txt --skip-update-check --format json --output output.json`,
		Run: run,
	}

	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "The domain to query for subdomains")
	rootCmd.Flags().StringVarP(&subdomainsFile, "subdomains-file", "s", "", "Path to the file containing subdomains to query (subdomains are separated by new lines)")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 30, "Number of concurrent threads for CNAME checks")
	rootCmd.Flags().BoolVarP(&skipUpdateCheck, "skip-update-check", "u", false, "Skip update check")
	rootCmd.Flags().StringVarP(&outputFileName, "output", "o", "output.md", "Name of the output file")
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "md", "Format of the output (md, json)")

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
		log.Fatalf("Please either provide a domain (-d <domain>) or a file with subdomains (-s <filename>)")
	}

	if RUNNING_ENVIRONMENT != "" {
		log.Info("The RUNNING_ENVIRONMENT is: ", RUNNING_ENVIRONMENT)
	}

	// makes it so that people don't have to explicitly specify the output file when choosing JSON as output format
	if outputFormat == "json" && outputFileName == "output.md" {
		outputFileName = "output.json"
	}

	if subdomainsFile != "" {
		log.Info("The provided subdomains file is: ", subdomainsFile)
	}

	// if the app runs inside a docker container, the output has to be written into `./output/output.md`, because
	// we will mount the CWD inside the container into `./output/`
	if RUNNING_ENVIRONMENT == "docker" {
		outputFileName = filepath.Join("output", outputFileName)

		// if the tool is run via docker and people pass in a subdomains file (-s) instead of a domain (-d)
		if subdomainsFile != "" && domain == "" {
			subdomainsFile = filepath.Join("output", subdomainsFile)
		}
	}

	log.Info("Output will be written to: ", outputFileName)

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

	var subdomains []string
	var err error
	// if the 'subdomainsFile' flag was provided
	if subdomainsFile != "" {
		// Check if the subdomains file exists
		if _, err := os.Stat(subdomainsFile); os.IsNotExist(err) {
			// If the file does not exist, log an error and exit
			log.Fatalf("The specified file with subdomains does not exist: %s", subdomainsFile)
		}
		// If the subdomains are provided when calling SubSnipe, we don't query crt.sh
		subdomains, err = readSubdomainsFile(subdomainsFile)
		if err != nil {
			log.Fatalf("Error reading subdomains file: %v", err)
		}
	} else if domain != "" {
		// Query crt.sh if a domain is provided
		subdomains, err = queryCRTSH()
		if err != nil {
			log.Fatalf("Error querying crt.sh: %v", err)
		}
	}

	if domain != "" {
		log.Info("Checking subdomains for: ", domain)
	}

	log.Infof("Number of subdomains to check: %d", len(subdomains))

	checkCNAMEs(subdomains)
}

// Queries crt.sh for subdomains of the given domain and writes unique common names to a file
func queryCRTSH() ([]string, error) {
	log.Info("Querying crt.sh for subdomains... (may take a moment)")

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response from crt.sh: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON response: %w", err)
	}

	log.Info("Done extracting subdomains from crt.sh")
	return extractUniqueCommonNames(data), nil
}

// Reads subdomains from a file and queries for their CNAME records concurrently
func checkCNAMEs(subdomains []string) {
	log.Info("Querying CNAME records for subdomains...")

	var wg sync.WaitGroup
	results := make(chan cnameResult, 100)
	sem := make(chan struct{}, threads)

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

	for _, domain := range subdomains {
		wg.Add(1)
		sem <- struct{}{}

		// Launch a goroutine for each CNAME query
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			queryAndSendCNAME(domain, results)
		}(domain)
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
		log.Infof("CNAME found for %s is: %s", domain, strings.TrimSpace(cname))
		results <- cnameResult{domain: domain, cname: strings.TrimSpace(cname)}
	}
}

// Writes the sorted CNAME query results to an output file with categorization based on exploitability
func writeResults() {
	switch outputFormat {
	case "json":
		writeJSONResults()
	default:
		writeMarkdownResults()
	}

	// for docker, we prepend 'output/' to the output file path. Thus, we get rid of this again now for logging purpose (to avoid confusion)
	if RUNNING_ENVIRONMENT == "docker" {
		outputFileName = strings.TrimPrefix(outputFileName, "output/")
	}
	log.Println("Results have been written to", outputFileName)
}

// Function to write results in JSON format grouped by exploitability
func writeJSONResults() {
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer outputFile.Close()

	type Result struct {
		Subdomain string `json:"subdomain"`
		CNAME     string `json:"cname"`
		Status    string `json:"status"`
	}

	// Create a struct to hold the grouped results
	groupedResults := struct {
		CouldBeExploitable    []Result `json:"couldBeExploitable"`
		NotExploitable        []Result `json:"notExploitable"`
		UnknownExploitability []Result `json:"unknownExploitability"`
	}{
		CouldBeExploitable:    []Result{},
		NotExploitable:        []Result{},
		UnknownExploitability: []Result{},
	}

	// Loop through couldBeExploitable array and append to grouped results
	for _, item := range couldBeExploitable {
		groupedResults.CouldBeExploitable = append(groupedResults.CouldBeExploitable, Result{
			Subdomain: extractSubdomain(item),
			CNAME:     extractCNAME(item),
			Status:    "Could be exploitable " + extractStatus(item),
		})
	}

	// Loop through notExploitable array and append to grouped results
	for _, item := range notExploitable {
		groupedResults.NotExploitable = append(groupedResults.NotExploitable, Result{
			Subdomain: extractSubdomain(item),
			CNAME:     extractCNAME(item),
			Status:    "Safe " + extractStatus(item),
		})
	}

	// Loop through unknownExploitability array and append to grouped results
	for _, item := range unknownExploitability {
		groupedResults.UnknownExploitability = append(groupedResults.UnknownExploitability, Result{
			Subdomain: extractSubdomain(item),
			CNAME:     extractCNAME(item),
			Status:    "Unknown Exploitability",
		})
	}

	// Encode the grouped results in JSON format and write to file
	encoder := json.NewEncoder(outputFile)
	encoder.SetIndent("", "  ") // for pretty-printing
	if err := encoder.Encode(groupedResults); err != nil {
		log.Fatalf("Error writing JSON output: %v", err)
	}
}

// Function to write results in Markdown format
func writeMarkdownResults() {
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Writing Could Be Exploitable section
	if len(couldBeExploitable) > 0 {
		outputFile.WriteString("### Could Be Exploitable\n\n")
		for _, item := range couldBeExploitable {
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
}

// Processes each CNAME query result, checking against fingerprints and service names
func processCNAMEResult(result cnameResult, fingerprints map[string]map[string]interface{}) {
	if result.err != nil || result.cname == "" {
		notFoundMsg := fmt.Sprintf("No CNAME record found for: %s", result.domain)
		log.Infof(notFoundMsg)
		return
	}

	// Check our fingerprints if the CNAME is known to be vulnerable to takeover
	directMatch, vulnerable, fingerprintText, hasNXDOMAINFlag := isVulnerableCNAME(result.cname, fingerprints)

	if directMatch {
		// If the TLD of the queried CNAME exists in our fingerprints and it flagged as 'vulnerable: true', we check for takeover
		if checkTakeover(result.cname, fingerprintText, hasNXDOMAINFlag) && vulnerable {
			log.Infof("+++ It's likely possible to takeover CNAME: %s +++", result.cname)
			serviceMsg := fmt.Sprintf("CNAME for %s is: %s (found matching fingerprint - '%s'): `Takeover Likely Possible!`", result.domain, result.cname, ifThenElse(vulnerable, "vulnerable", "safe"))
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
