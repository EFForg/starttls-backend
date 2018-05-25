package checker

import (
	"errors"
	"net"
)

// Reports an error during the domain checks.
func (d DomainResult) reportError(err error) DomainResult {
	d.Status = Error
	d.Message = err.Error()
	return d
}

// DomainResult wraps all the results for a particular mail domain.
type DomainResult struct {
	// Domain being checked against.
	Domain string `json:"domain"`
	// Message if a failure or error occurs on the domain lookup level.
	Message string `json:"message,omitempty"`
	// Status of this check, inherited from the results of preferred hostnames.
	Status CheckStatus `json:"status"`
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

func lookupHostnames(domain string) ([]string, []string, error) {
	mxs, err := net.LookupMX(domain)
	if err != nil || len(mxs) == 0 {
		return nil, nil, errors.New("No MX records found")
	}
	hostnames := make([]string, 0)
	for _, mx := range mxs {
		hostnames = append(hostnames, mx.Host)
	}
	// TODO: support >1 hostname with same MX priority
	return hostnames, []string{hostnames[0]}, nil
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
	hostnames, preferredHostnames, err := lookupHostnames(domain)
	if err != nil {
		return result.reportError(err)
	}
	result.PreferredHostnames = preferredHostnames
	result.HostnameResults = make(map[string]HostnameResult)
	for _, hostname := range hostnames {
		result.HostnameResults[hostname] = CheckHostname(domain, hostname, mxHostnames)
	}
	for _, hostname := range preferredHostnames {
		result.Status = SetStatus(result.Status, result.HostnameResults[hostname].Status)
	}
	return result
}
