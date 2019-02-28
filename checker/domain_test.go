package checker

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// fake DNS map for "resolving" MX lookups
var mxLookup = map[string][]string{
	"empty":         []string{},
	"changes":       []string{"changes"},
	"domain":        []string{"hostname1", "hostname2"},
	"domain.tld":    []string{"mail2.domain.tld", "mail1.domain.tld"},
	"noconnection":  []string{"noconnection", "noconnection"},
	"noconnection2": []string{"noconnection", "nostarttlsconnect"},
	"nostarttls":    []string{"nostarttls", "noconnection"},
}

// Fake hostname checks :)
var hostnameResults = map[string]Result{
	"noconnection": Result{
		Status: 3,
		Checks: map[string]*Result{
			Connectivity: {Connectivity, 3, nil, nil},
		},
	},
	"nostarttls": Result{
		Status: 2,
		Checks: map[string]*Result{
			Connectivity: {Connectivity, 0, nil, nil},
			STARTTLS:     {STARTTLS, 2, nil, nil},
		},
	},
	"nostarttlsconnect": Result{
		Status: 3,
		Checks: map[string]*Result{
			Connectivity: {Connectivity, 0, nil, nil},
			STARTTLS:     {STARTTLS, 3, nil, nil},
		},
	},
}

func mockCheckMTASTS(domain string, hostnameResults map[string]HostnameResult) *MTASTSResult {
	r := MakeMTASTSResult()
	r.Mode = "testing"
	return r
}

func mockLookupMX(domain string) ([]*net.MX, error) {
	if domain == "error" {
		return nil, fmt.Errorf("No MX records found")
	}
	result := []*net.MX{}
	for _, host := range mxLookup[domain] {
		result = append(result, &net.MX{Host: host})
	}
	return result, nil
}

func mockCheckHostname(domain string, hostname string) HostnameResult {
	if result, ok := hostnameResults[hostname]; ok {
		return HostnameResult{
			Result:    &result,
			Timestamp: time.Now(),
		}
	}
	// For caching test: "changes" result changes after first scan
	if hostname == "changes" {
		hostnameResults["changes"] = hostnameResults["nostarttls"]
	}
	// by default return successful check
	return HostnameResult{
		Result: &Result{
			Status: 0,
			Checks: map[string]*Result{
				Connectivity: {Connectivity, 0, nil, nil},
				STARTTLS:     {STARTTLS, 0, nil, nil},
				Certificate:  {Certificate, 0, nil, nil},
				Version:      {Version, 0, nil, nil},
			},
		},
		Timestamp: time.Now(),
	}
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
	performTestsWithCacheTimeout(t, tests, time.Hour)
}

func performTestsWithCacheTimeout(t *testing.T, tests []domainTestCase, cacheExpiry time.Duration) {
	c := Checker{
		Timeout:               time.Second,
		Cache:                 MakeSimpleCache(cacheExpiry),
		lookupMXOverride:      mockLookupMX,
		checkHostnameOverride: mockCheckHostname,
		checkMTASTSOverride:   mockCheckMTASTS,
	}
	for _, test := range tests {
		if test.expectedHostnames == nil {
			test.expectedHostnames = mxLookup[test.domain]
		}
		got := c.CheckDomain(test.domain, test.expectedHostnames).Status
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

func TestWildcardHostnames(t *testing.T) {
	tests := []domainTestCase{
		{"domain.tld", []string{".tld"}, DomainBadHostnameFailure},
		{"domain.tld", []string{".domain.tld"}, DomainSuccess},
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

func TestHostnameScanCached(t *testing.T) {
	// "Changes" result status should change from 0 => 5 after first scan,
	// but since it's cached, we should always get 0 (the result from the
	// first scan)
	delete(hostnameResults, "changes")
	tests := []domainTestCase{
		{domain: "changes", expect: 0},
		{domain: "changes", expect: 0},
		{domain: "changes", expect: 0}}
	performTests(t, tests)
}

func TestHostnameScanExpires(t *testing.T) {
	delete(hostnameResults, "changes")
	tests := []domainTestCase{
		{domain: "changes", expect: 0},
		{domain: "changes", expect: 4}}
	performTestsWithCacheTimeout(t, tests, 0)
}

func TestNewSampleDomainResult(t *testing.T) {
	NewSampleDomainResult("example.com")
}
