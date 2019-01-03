package checker

import (
	"net"
	"time"
)

// A Checker is used to run checks against SMTP domains and hostnames.
type Checker struct {
	Timeout       time.Duration
	Cache         ScanCache // No cache if nil?
	lookupMX      func(string) ([]*net.MX, error)
	checkHostname func(string, string) HostnameResult
}

func (c Checker) timeout() time.Duration {
	if &c.Timeout != nil {
		return c.Timeout
	}
	return 10 * time.Second
}

func (c Checker) cache() ScanCache {
	if &c.Cache == nil {
		c.Cache = CreateSimpleCache(10 * time.Minute)
	}
	return c.Cache
}
