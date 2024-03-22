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

func TestIsVulnerableCNAME_NotVulnerable(t *testing.T) {
	// Setup mock fingerprints data including both vulnerable and non-vulnerable entries
	fingerprints := map[string]map[string]interface{}{
		"vulnerable.com": {
			"cname":        []interface{}{"vulnerable.com"},
			"vulnerable":   true,
			"fingerprint":  "Vulnerable Service",
			"nxdomain":     false,
		},
		"safe.com": {
			"cname":        []interface{}{"safe.com"},
			"vulnerable":   false,
			"fingerprint":  "Safe Service",
			"nxdomain":     false,
		},
	}

	// Test a non-vulnerable CNAME
	safeCNAME := "subdomain.safe.com."
	directMatch, vulnerable, fingerprintText, hasNXDOMAINFlag := isVulnerableCNAME(safeCNAME, fingerprints)

	// Assertions
	assert.True(t, directMatch, "Expected a direct match for the CNAME")
	assert.False(t, vulnerable, "Expected the CNAME to be non-vulnerable")
	assert.Equal(t, "Safe Service", fingerprintText, "Expected the correct fingerprint text")
	assert.False(t, hasNXDOMAINFlag, "Expected the NXDOMAIN flag to be false")
}

func TestIsVulnerableCNAME_NotFound(t *testing.T) {
	// Setup mock fingerprints data
	fingerprints := map[string]map[string]interface{}{
		"vulnerable.com": {
			"cname":        []interface{}{"vulnerable.com"},
			"vulnerable":   true,
			"fingerprint":  "Vulnerable Service",
			"nxdomain":     false,
		},
	}

	// Test a CNAME that is not present in the fingerprints
	unknownCNAME := "unknown.com."
	directMatch, vulnerable, fingerprintText, hasNXDOMAINFlag := isVulnerableCNAME(unknownCNAME, fingerprints)

	assert.False(t, directMatch, "Expected no direct match for the CNAME")
	assert.False(t, vulnerable, "Expected the CNAME to be considered non-vulnerable by default")
	assert.Equal(t, "", fingerprintText, "Expected an empty fingerprint text")
	assert.False(t, hasNXDOMAINFlag, "Expected the NXDOMAIN flag to be false for an unknown CNAME")
}

func TestExtractServiceName(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		expectedSLD  string
	}{
		{"WithSubdomain", "sub.example.com.", "example"},
		{"WithMultipleSubdomains", "deep.sub.example.com.", "example"},
		{"OnlySLDAndTLD", "example.com.", "example"},
		{"SingleLabelDomain", "localhost.", ""},
		{"EmptyDomain", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sld := extractServiceName(test.domain)
			assert.Equal(t, test.expectedSLD, sld, "Extracted SLD should match the expected value for "+test.domain)
		})
	}
}

func TestAppendResultBasedOnVulnerability(t *testing.T) {
	// Reset global variables for a clean test environment
	isExploitable = []string{}
	notExploitable = []string{}

	// Test adding a vulnerable subdomain
	appendResultBasedOnVulnerability(true, "vulnerable.example.com")
	assert.Contains(t, isExploitable, "vulnerable.example.com", "The vulnerable domain should be added to the isExploitable list")

	// Test adding a non-vulnerable subdomain
	appendResultBasedOnVulnerability(false, "safe.example.com")
	assert.
	Contains(t, notExploitable, "safe.example.com", "The non-vulnerable domain should be added to the notExploitable list")
}