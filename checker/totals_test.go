package checker

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func TestCheckCSV(t *testing.T) {
	in := "empty\ndomain\ndomain.tld\nnoconnection\nnoconnection2\nnostarttls\n"
	reader := csv.NewReader(strings.NewReader(in))

	c := Checker{
		Cache:                 MakeSimpleCache(10 * time.Minute),
		lookupMXOverride:      mockLookupMX,
		checkHostnameOverride: mockCheckHostname,
		checkMTASTSOverride:   mockCheckMTASTS,
	}
	totals := DomainTotals{}
	c.CheckCSV(reader, &totals)

	if totals.Attempted != 6 {
		t.Errorf("Expected 6 attempted connections, got %d", totals.Attempted)
	}
	if totals.Connected != 4 {
		t.Errorf("Expected 4 successfully connecting domains, got %d", totals.Connected)
	}
	if totals.MTASTSTesting != 4 {
		t.Errorf("Expected 4 domains in MTA-STS testing mode, got %d", totals.MTASTSTesting)
	}
}
