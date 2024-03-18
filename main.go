package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/fatih/color"
)

type cnameResult struct {
	domain string
	cname  string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <domain>")
		os.Exit(1)
	}

	printIntro()

	// check if the AppVersion was already set during compilation - otherwise manually get it from `./VERSION`
	CheckAppVersion()
	color.Yellow("Current version: %s\n\n", AppVersion)

	domain := os.Args[1]
	log.Info("Checking subdomains for: ", domain)

	queryCRTSH(domain)
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

func queryCRTSH(domain string) {
	log.Infof("Getting all domains from crt.sh... (may take a moment)")

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		log.Error("Error querying crt.sh:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error reading response body:", err)
		return
	}

	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Error("Error unmarshaling JSON:", err)
		return
	}

	uniqueCommonNames := make(map[string]bool)
	for _, entry := range data {
		if cn, ok := entry["common_name"].(string); ok {
			uniqueCommonNames[cn] = true
		}
	}

	outputFile := "subdomains.txt"
	file, err := os.Create(outputFile)
	if err != nil {
		log.Error("Error creating output file:", err)
		return
	}
	defer file.Close()

	for cn := range uniqueCommonNames {
		file.WriteString(cn + "\n")
	}

	log.Info("Unique common names have been extracted to ", outputFile)
	checkCNAMEs(outputFile)
}

func checkCNAMEs(fileName string) {
    // Maximum number of concurrent goroutines
    maxConcurrency := 20
    sem := make(chan struct{}, maxConcurrency)

    file, err := os.Open(fileName)
    if err != nil {
        log.Error("Error opening file:", err)
        return
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    var wg sync.WaitGroup

    results := make(chan cnameResult, 100)

    go func() {
        for result := range results {
            if result.cname == "" {
                log.Warnf("No CNAME record found for: %s", result.domain)
            } else {
                log.Infof("CNAME for %s is: %s", result.domain, result.cname)
            }
        }
    }()

    for scanner.Scan() {
        domain := scanner.Text()
        wg.Add(1)
        sem <- struct{}{} // Acquire semaphore
        go func(domain string) {
            defer wg.Done()
            defer func() { <-sem }() // Release semaphore
            cname, err := exec.Command("dig", "+short", "CNAME", domain).Output()
            if err != nil {
                log.Errorf("Error querying CNAME for %s: %v", domain, err)
                results <- cnameResult{domain: domain, cname: ""}
                return
            }
            results <- cnameResult{domain: domain, cname: string(cname)}
        }(domain)
    }

    wg.Wait()
    close(results)

    if err := scanner.Err(); err != nil {
        log.Error("Error reading file:", err)
    }
}
