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

// Mock implementation for lookup and checker

type mockLookup struct{}
type mockChecker struct{}

func (*mockLookup) lookupHostname(domain string) ([]string, error) {
	if domain == "error" {
		return nil, fmt.Errorf("No MX records found")
	}
	return mxLookup[domain], nil
}

func (*mockChecker) checkHostname(domain string, hostname string) HostnameResult {
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
		got := performCheck(DomainQuery{
			Domain:            test.domain,
			ExpectedHostnames: test.expectedHostnames,
			hostnameLookup:    &mockLookup{},
			hostnameChecker:   &mockChecker{},
		}).Status
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
