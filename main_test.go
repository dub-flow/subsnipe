package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestQueryCRTSH(t *testing.T) {
	// Start HTTP mock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock the crt.sh response
	httpmock.RegisterResponder("GET", "https://crt.sh/?q=test.com&output=json",
		httpmock.NewStringResponder(200, `[{"common_name":"subdomain.test.com"}]`))

	// Set global variable 'domain' for the test
	domain = "test.com"

	// Call the function to test
	queryCRTSH()

	// Verify that the "crt-subdomains.txt" file is created and contains the expected content
	content, err := ioutil.ReadFile("crt-subdomains.txt")
	assert.NoError(t, err, "Expected no error reading the crt-subdomains.txt file")
	assert.Contains(t, string(content), "subdomain.test.com", "The file should contain the subdomain 'subdomain.test.com'")
	
	// Clean up the generated file
	os.Remove("crt-subdomains.txt")
}

func TestIsVulnerableCNAME_Vulnerable(t *testing.T) {
	// Setup a mock fingerprints data
	fingerprints := map[string]map[string]interface{}{
		"vulnerable.com": {
			"cname":        []interface{}{"vulnerable.com"},
			"vulnerable":   true,
			"fingerprint":  "Vulnerable Service",
			"nxdomain":     false,
		},
	}

	// Test a vulnerable CNAME
	vulnerableCNAME := "subdomain.vulnerable.com."
	directMatch, vulnerable, fingerprintText, hasNXDOMAINFlag := isVulnerableCNAME(vulnerableCNAME, fingerprints)

	assert.True(t, directMatch, "Expected a direct match for the CNAME")
	assert.True(t, vulnerable, "Expected the CNAME to be vulnerable")
	assert.Equal(t, "Vulnerable Service", fingerprintText, "Expected the correct fingerprint text")
	assert.False(t, hasNXDOMAINFlag, "Expected the NXDOMAIN flag to be false")
}
