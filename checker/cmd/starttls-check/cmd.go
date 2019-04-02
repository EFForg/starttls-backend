package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

var out io.Writer = os.Stdout

func setFlags() (domain, filePath, url *string, column *int, aggregate *bool) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	domain = flag.String("domain", "", "Domain to check")
	filePath = flag.String("file", "", "File path to a CSV of domains to check")
	url = flag.String("url", "", "URL of a CSV of domains to check")
	column = flag.Int("column", 0, "Zero indexed column of domains")
	aggregate = flag.Bool("aggregate", false, "Write aggregated MTA-STS statistics to database, specified by ENV")

	flag.Parse()
	if *domain == "" && *filePath == "" && *url == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *domain != "" && (*column != 0 || *aggregate == true) {
		log.Println("column and aggregate are not supported for single domain checks")
		flag.PrintDefaults()
		os.Exit(1)
	}
	return
}

// Run a series of security checks on an MTA domain.
// =================================================
// Validating (START)TLS configurations for all MX domains.
func main() {
	domain, filePath, url, column, aggregate := setFlags()

	c := checker.Checker{
		Cache: checker.MakeSimpleCache(10 * time.Minute),
	}
	var resultHandler checker.ResultHandler
	resultHandler = &domainWriter{}

	if *domain != "" {
		// Handle single domain and return
		result := c.CheckDomain(*domain, nil)
		resultHandler.HandleDomain(result)
		os.Exit(0)
	}

	var instream io.Reader
	var label string
	if *filePath != "" {
		csvFile, err := os.Open(*filePath)
		defer csvFile.Close()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		instream = bufio.NewReader(csvFile)
		label = csvFile.Name()
	} else {
		resp, err := http.Get(*url)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		instream = resp.Body
		label = *url
	}

	domainReader := csv.NewReader(instream)
	if *aggregate {
		c = checker.Checker{
			CheckHostname: checker.NoopCheckHostname,
		}
		resultHandler = &checker.DomainTotals{
			Time:   time.Now(),
			Source: label,
		}
	}
	// Assume domains are in the 0th column, eg just a newline-separated list
	// of domains. Could pass this is a flag.
	c.CheckCSV(domainReader, resultHandler, *column)
	fmt.Fprintln(out, resultHandler)
}

type domainWriter struct{}

func (w domainWriter) HandleDomain(r checker.DomainResult) {
	b, err := json.Marshal(r)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Fprintln(out, string(b))
}
