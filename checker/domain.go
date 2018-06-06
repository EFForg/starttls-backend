package checker

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Reports an error during the domain checks.
func (d DomainResult) reportError(err error) DomainResult {
	d.Status = DomainError
	d.Message = err.Error()
	return d
}

type DomainStatus int32

// In order of precedence.
const (
	DomainSuccess           DomainStatus = 0
	DomainWarning           DomainStatus = 1
	DomainFailure           DomainStatus = 2
	DomainError             DomainStatus = 3
	DomainNoSTARTTLSFailure DomainStatus = 4
	DomainCouldNotConnect   DomainStatus = 5
)

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
	// The list of hostnames which impact the Status of this result.
	// Determined by the hostnames with the lowest MX priority.
	PreferredHostnames []string `json:"preferred_hostnames"`
	// Expected MX hostnames supplied by the caller of CheckDomain.
	MxHostnames []string `json:"mx_hostnames,omitempty"`
	// Extra global results
	ExtraResults map[string]CheckResult `json:"extra_results,omitempty"`
}

func lookupMXWithTimeout(domain string) ([]*net.MX, error) {
	const timeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	var r net.Resolver
	return r.LookupMX(ctx, domain)
}

func lookupHostnames(domain string) ([]string, error) {
	mxs, err := lookupMXWithTimeout(domain)
	if err != nil || len(mxs) == 0 {
		return nil, fmt.Errorf("No MX records found")
	}
	hostnames := make([]string, 0)
	for _, mx := range mxs {
		hostnames = append(hostnames, mx.Host)
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
//   `mxHostnames` is a list of expected hostnames for certificate validation.
func CheckDomain(domain string, mxHostnames []string) DomainResult {
	// 1. Look up hostnames
	// 2. Perform and aggregate checks from those hostnames.
	// 3. Set a summary message.
	result := DomainResult{Domain: domain, MxHostnames: mxHostnames}
	hostnames, err := lookupHostnames(domain)
	if err != nil {
		return result.reportError(err)
	}
	checkedHostnames := make([]string, 0)
	result.HostnameResults = make(map[string]HostnameResult)
	for _, hostname := range hostnames {
		result.HostnameResults[hostname] = CheckHostname(domain, hostname, mxHostnames)
		if result.HostnameResults[hostname].couldConnect() {
			checkedHostnames = append(checkedHostnames, hostname)
		}
	}
	result.PreferredHostnames = checkedHostnames

	// Derive Domain code from Hostname results.
	// We couldn't connect to any of those hostnames.
	if len(checkedHostnames) == 0 {
		result.Status = DomainCouldNotConnect
		return result
	}
	for _, hostname := range checkedHostnames {
		hostnameResult := result.HostnameResults[hostname]
		// Any of the connected hostnames don't support STARTTLS.
		if !hostnameResult.couldSTARTTLS() {
			result.Status = DomainNoSTARTTLSFailure
			return result
		}
		result.Status = DomainStatus(
			SetStatus(CheckStatus(result.Status), CheckStatus(result.HostnameResults[hostname].Status)))
	}
	return result
}
