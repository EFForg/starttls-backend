package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// Reports an error during the domain checks.
func (d DomainResult) reportError(err error) DomainResult {
	d.Status = DomainError
	d.Message = err.Error()
	return d
}

// DomainStatus indicates the overall status of a single domain.
type DomainStatus int32

// In order of precedence.
const (
	DomainSuccess            DomainStatus = 0
	DomainWarning            DomainStatus = 1
	DomainFailure            DomainStatus = 2
	DomainError              DomainStatus = 3
	DomainNoSTARTTLSFailure  DomainStatus = 4
	DomainCouldNotConnect    DomainStatus = 5
	DomainBadHostnameFailure DomainStatus = 6
)

// DomainQuery wraps the parameters we need to perform a domain check.
type DomainQuery struct {
	// Domain being checked.
	Domain string
	// Expected hostnames in MX records for Domain
	ExpectedHostnames []string
	// Unexported implementations for fns that make network requests
	hostnameLookup
	hostnameChecker
}

// Looks up what hostnames are correlated with a particular domain.
type hostnameLookup interface {
	lookupHostname(string) ([]string, error)
}

// Performs a series of checks on a particular domain, hostname combo.
type hostnameChecker interface {
	checkHostname(string, string) HostnameResult
}

// DomainResult wraps all the results for a particular mail domain.
type DomainResult struct {
	// Domain being checked against.
	Domain string `json:"domain"`
	// Message if a failure or error occurs on the domain lookup level.
	Message string `json:"message,omitempty"`
	// Status of this check, inherited from the results of preferred hostnames.
	Status DomainStatus `json:"status"`
	// Results of this check, on each hostname.
	HostnameResults map[string]HostnameResult `json:"results"`
	// The list of hostnames which will impact the Status of this result.
	// It discards mailboxes that we can't connect to.
	PreferredHostnames []string `json:"preferred_hostnames"`
	// Expected MX hostnames supplied by the caller of CheckDomain.
	MxHostnames []string `json:"mx_hostnames,omitempty"`
	// Extra global results
	ExtraResults map[string]CheckResult `json:"extra_results,omitempty"`
}

type tlsChecker struct{}

func (*tlsChecker) checkHostname(domain string, hostname string) HostnameResult {
	return CheckHostname(domain, hostname)
}

func (d DomainResult) setStatus(status DomainStatus) DomainResult {
	d.Status = DomainStatus(SetStatus(CheckStatus(d.Status), CheckStatus(status)))
	return d
}

func lookupMXWithTimeout(domain string) ([]*net.MX, error) {
	const timeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	var r net.Resolver
	return r.LookupMX(ctx, domain)
}

type dnsLookup struct{}

func (*dnsLookup) lookupHostname(domain string) ([]string, error) {
	domainASCII, err := idna.ToASCII(domain)
	if err != nil {
		return nil, fmt.Errorf("domain name %s couldn't be converted to ASCII", domain)
	}
	mxs, err := lookupMXWithTimeout(domainASCII)
	if err != nil || len(mxs) == 0 {
		return nil, fmt.Errorf("No MX records found")
	}
	hostnames := make([]string, 0)
	for _, mx := range mxs {
		hostnames = append(hostnames, strings.ToLower(mx.Host))
	}
	return hostnames, nil
}

// CheckDomain performs all associated checks for a particular domain.
// First performs an MX lookup, then performs subchecks on each of the
// resulting hostnames.
//
// The status of DomainResult is inherited from the check status of the MX
// records with highest priority. This check succeeds only if the hostname
// checks on the highest priority mailservers succeed.
//
//   `domain` is the mail domain to perform the lookup on.
//   `mxHostnames` is the list of expected hostnames.
//     If `mxHostnames` is nil, we don't validate the DNS lookup.
func CheckDomain(domain string, mxHostnames []string) DomainResult {
	return performCheck(DomainQuery{
		Domain:            domain,
		ExpectedHostnames: mxHostnames,
		hostnameLookup:    &dnsLookup{},
		hostnameChecker:   &tlsChecker{},
	})
}

func performCheck(query DomainQuery) DomainResult {
	result := DomainResult{
		Domain:          query.Domain,
		MxHostnames:     query.ExpectedHostnames,
		HostnameResults: make(map[string]HostnameResult),
	}
	// 1. Look up hostnames
	// 2. Perform and aggregate checks from those hostnames.
	// 3. Set a summary message.
	hostnames, err := query.lookupHostname(query.Domain)
	if err != nil {
		return result.reportError(err)
	}
	checkedHostnames := make([]string, 0)
	for _, hostname := range hostnames {
		hostnameResult := query.checkHostname(query.Domain, hostname)
		result.HostnameResults[hostname] = hostnameResult
		if hostnameResult.couldConnect() {
			checkedHostnames = append(checkedHostnames, hostname)
		}
	}
	result.PreferredHostnames = checkedHostnames

	// Derive Domain code from Hostname results.
	if len(checkedHostnames) == 0 {
		// We couldn't connect to any of those hostnames.
		return result.setStatus(DomainCouldNotConnect)
	}
	for _, hostname := range checkedHostnames {
		hostnameResult := result.HostnameResults[hostname]
		// Any of the connected hostnames don't support STARTTLS.
		if !hostnameResult.couldSTARTTLS() {
			return result.setStatus(DomainNoSTARTTLSFailure)
		}
		// Any of the connected hostnames don't have a match?
		if query.ExpectedHostnames != nil && !hasValidName(query.ExpectedHostnames, hostname) {
			return result.setStatus(DomainBadHostnameFailure)
		}
		result = result.setStatus(DomainStatus(hostnameResult.Status))
	}
	return result
}
