package checker

import (
	"context"
	"net"
	"time"
)

// A Checker is used to run checks against SMTP domains and hostnames.
type Checker struct {
	// Timeout specifies the maximum timeout for network requests made during
	// checks.
	// If nil, a default timeout of 10 seconds is used.
	Timeout time.Duration

	// Cache specifies the hostname scan cache store and expire time.
	// If `nil`, then scans are not cached.
	Cache *ScanCache

	// lookupMXOverride specifies an alternate function to retrieve hostnames for a given
	// domain. It is used to mock DNS lookups during testing.
	lookupMXOverride func(string) ([]*net.MX, error)

	// CheckHostname defines the function that should be used to check each hostname.
	// If nil, FullCheckHostname (all hostname checks) will be used.
	CheckHostname func(context.Context, string, string, time.Duration) HostnameResult

	// checkMTASTSOverride is used to mock MTA-STS checks.
	checkMTASTSOverride func(string, map[string]HostnameResult) *MTASTSResult
}

func (c *Checker) timeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	return 10 * time.Second
}
