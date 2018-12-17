package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

// Expects domains to be delimited by newlines.
func domainsFromFile(filename string) (string, error) {
	buff, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(buff), nil
}

func parseCSV(data string) ([][2]string, error) {
	domains := [][2]string{}
	r := csv.NewReader(strings.NewReader(data))
	records, err := r.ReadAll()
	if err != nil {
		return domains, err
	}
	for _, record := range records {
		domains = append(domains, [2]string{record[0], record[2]})
	}
	return domains, nil

}

func statusToString(status checker.DomainStatus) string {
	if status == 0 {
		return "SUCCESS"
	} else if status == 1 {
		return "WARNING"
	} else if status == 2 {
		return "FAILURE"
	} else if status == 3 {
		return "ERROR"
	} else if status == 4 {
		return "BAD_TLS"
	} else if status == 5 {
		return "NO_CONNECT"
	} else if status == 6 {
		return "BAD_HOSTNAME"
	}
	return fmt.Sprintf("UNKNOWN_%d", status)
}

func checkDomains(domains [][2]string, logFile string) {
	w := csv.NewWriter(os.Stdout)
	results := make(map[string]checker.DomainResult)
	cache := checker.CreateSimpleCache(10 * time.Minute)
	for _, domainInfo := range domains {
		result := checker.CheckDomain(domainInfo[0],
			strings.Split(domainInfo[1], ","), 10*time.Second, cache)
		results[result.Domain] = result
		w.Write(append(domainInfo[:], statusToString(result.Status)))
		w.Flush()
	}
	if len(logFile) > 0 {
		resultsStr, _ := json.MarshalIndent(results, "", "  ")
		ioutil.WriteFile(logFile, resultsStr, 0644)
	}
}

// Run a series of security checks on an MTA domain.
// =================================================
// Validating (START)TLS configurations for all MX domains.
//
// CLI arguments
// =============
//     -domain <domain> The domain to perform checks against.
//     -csv <filepath>  CSV containing list of domains to perform check.
//
func main() {
	// 1. Setup and parse arguments.
	flag.Usage = func() {
		log.Printf("\nNOTE: All checks are enabled by default. " +
			"Setting any individual 'enable check' flag will disable " +
			"all checks other than the ones explicitly specified.\n\n")
		log.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	domainStr := flag.String("domain", "", "Domain to check TLS for.")
	fileStr := flag.String("csv", "", "Filename containing CSV of domains to check.")
	logFile := flag.String("log", "", "File to export more info about checks.")
	flag.Parse()
	// in, _ := os.Stdin.Stat()
	// 	if *domainStr == "" && *fileStr == "" {
	// 		flag.PrintDefaults()
	// 		os.Exit(1)
	// 	}

	if *domainStr != "" {
		cache := checker.CreateSimpleCache(10 * time.Minute)
		result := checker.CheckDomain(*domainStr, nil, 10*time.Second, cache)
		b, err := json.Marshal(result)
		if err != nil {
			log.Printf("%q", err)
		}
		log.Println(string(b))
	}
	// Try reading domains from file. If none provided, read from stdin.
	var data string
	if *fileStr != "" {
		fileData, err := domainsFromFile(*fileStr)
		if err != nil {
			log.Fatalf("couldn't read %s: %v", *fileStr, err)
		}
		data = fileData
	} else {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("couldn't read from Stdin: %v", err)
		}
		data = string(bytes)
	}
	domains, err := parseCSV(data)
	if err != nil {
		log.Fatalf("couldn't parse %s: %v", *fileStr, err)
	}
	checkDomains(domains, *logFile)
}
