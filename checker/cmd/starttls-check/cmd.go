package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/EFForg/starttls-check/checker"
)

// Expects domains to be delimited by newlines.
func domainsFromFile(filename string) ([]string, error) {
	buff, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	allContent := string(buff)
	// Filter empty lines from domain list
	filterDomains := make([]string, 0)
	for _, line := range strings.Split(allContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		filterDomains = append(filterDomains, trimmed)
	}
	return filterDomains, nil
}

// Run a series of security checks on an MTA domain.
// =================================================
// Validating (START)TLS configurations for all MX domains.
//
// CLI arguments
// =============
//     -domain <domain> The domain to perform checks against.
//
func main() {
	// 1. Setup and parse arguments.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nNOTE: All checks are enabled by default. "+
			"Setting any individual 'enable check' flag will disable "+
			"all checks other than the ones explicitly specified.\n\n")
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	domainStr := flag.String("domain", "", "Required: Domain to check TLS for.")
	flag.Parse()
	if *domainStr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	result := checker.CheckDomain(*domainStr, nil)
	b, err := json.Marshal(result)
	if err != nil {
		fmt.Printf("%q", err)
	}
	fmt.Println(string(b))
}
