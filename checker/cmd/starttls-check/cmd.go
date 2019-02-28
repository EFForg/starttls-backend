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

func setFlags() (domain, filePath, url *string) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	domain = flag.String("domain", "", "Domain to check")
	filePath = flag.String("file", "", "File path to a CSV of domains to check")
	url = flag.String("url", "", "URL of a CSV of domains to check")

	flag.Parse()
	if *domain == "" && *filePath == "" && *url == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	return
}

// Run a series of security checks on an MTA domain.
// =================================================
// Validating (START)TLS configurations for all MX domains.
func main() {
	domain, filePath, url := setFlags()

	c := checker.Checker{
		Cache: checker.MakeSimpleCache(10 * time.Minute),
	}

	if *domain != "" {
		// Handle single domain and return
		result := c.CheckDomain(*domain, nil)
		w.HandleDomain(result)
		os.Exit(0)
	}

	var instream io.Reader
	if *filePath != "" {
		csvFile, err := os.Open(*filePath)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		instream = bufio.NewReader(csvFile)
	} else {
		resp, err := http.Get(*url)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		instream = resp.Body
	}

	domainReader := csv.NewReader(instream)
	c.CheckCSV(domainReader, &w)
}

type DomainWriter struct{}

func (w DomainWriter) HandleDomain(r DomainResult) {
	b, err := json.Marshal(result)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
