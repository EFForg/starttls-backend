package checker

import (
	"fmt"
	"testing"
)

// fake DNS map for "resolving" MX lookups
var mxLookup = map[string][]string{
	"empty":         []string{},
	"domain":        []string{"hostname1", "hostname2"},
	"noconnection":  []string{"noconnection", "noconnection"},
	"noconnection2": []string{"noconnection", "nostarttlsconnect"},
	"nostarttls":    []string{"nostarttls", "noconnection"},
}

// Fake hostname checks :)
var hostnameResults = map[string]HostnameResult{
	"noconnection": HostnameResult{
		Status: 3,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 3, nil},
		},
	},
	"nostarttls": HostnameResult{
		Status: 2,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 0, nil},
			"starttls":     {"starttls", 2, nil},
		},
	},
	"nostarttlsconnect": HostnameResult{
		Status: 3,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 0, nil},
			"starttls":     {"starttls", 3, nil},
		},
	},
}

// Mock query object that also fulfills the DomainQuery interface.
type mockQuery struct {
	Domain            string
	ExpectedHostnames []string
}

// Mock implementation for mockQuery.

func (q mockQuery) lookupHostnames() ([]string, error) {
	if q.Domain == "error" {
		return nil, fmt.Errorf("No MX records found")
	}
	return mxLookup[q.Domain], nil
}

func (q mockQuery) checkHostname(hostname string) HostnameResult {
	if result, ok := hostnameResults[hostname]; ok {
		return result
	}
	// by default return successful check
	return HostnameResult{Status: 0, Checks: map[string]CheckResult{
		"connectivity": {"connectivity", 0, nil},
		"starttls":     {"starttls", 0, nil},
		"certificate":  {"certificate", 0, nil},
		"version":      {"version", 0, nil}}}
}

func (q mockQuery) getDomain() string {
	return q.Domain
}

func (q mockQuery) getExpectedHostnames() []string {
	return q.ExpectedHostnames
}

// Test helpers.

// If expectedHostnames is nil, we just assume that whatever lookup occurs is correct.
type domainTestCase struct {
	// Test case parameters
	domain            string
	expectedHostnames []string
	// Expected result of test case.
	expect DomainStatus
}

// Perform a single test check
func (test domainTestCase) check(t *testing.T, got DomainStatus) {
	if got != test.expect {
		t.Errorf("Testing %s with hostnames %s: Expected status code %d, got code %d",
			test.domain, test.expectedHostnames, test.expect, got)
	}
}

func performTests(t *testing.T, tests []domainTestCase) {
	for _, test := range tests {
		if test.expectedHostnames == nil {
			test.expectedHostnames = mxLookup[test.domain]
		}
		got := performCheck(mockQuery{Domain: test.domain, ExpectedHostnames: test.expectedHostnames}).Status
		test.check(t, got)
	}
}

// Test cases.

func TestBadMXLookup(t *testing.T) {
	tests := []domainTestCase{
		{"empty", []string{}, DomainCouldNotConnect},
	}
	performTests(t, tests)
}

func TestNoExpectedHostnames(t *testing.T) {
	tests := []domainTestCase{
		{"domain", []string{}, DomainBadHostnameFailure},
		{"domain", []string{"hostname"}, DomainBadHostnameFailure},
		{"domain", []string{"hostname1"}, DomainBadHostnameFailure},
		{"domain", []string{"hostname1", "hostname2"}, DomainSuccess},
		{"domain", nil, DomainSuccess},
	}
	performTests(t, tests)
}

func TestHostnamesNoConnection(t *testing.T) {
	tests := []domainTestCase{
		{domain: "noconnection", expect: DomainCouldNotConnect},
	}
	performTests(t, tests)
}

func TestHostnamesNoSTARTTLS(t *testing.T) {
	tests := []domainTestCase{
		{domain: "nostarttls", expect: DomainNoSTARTTLSFailure},
		{domain: "noconnection2", expect: DomainNoSTARTTLSFailure},
	}
	performTests(t, tests)
}
