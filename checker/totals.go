package checker

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// AggregatedScan compiles aggregated stats across domains.
// Implements ResultHandler.
type AggregatedScan struct {
	Time              time.Time
	Source            string
	Attempted         int
	WithMXs           int
	MTASTSTesting     int
	MTASTSTestingList []string
	MTASTSEnforce     int
	MTASTSEnforceList []string
}

// HandleDomain adds the result of a single domain scan to aggregated stats.
func (a *AggregatedScan) HandleDomain(r DomainResult) {
	a.Attempted++
	// Show progress.
	if a.Attempted%1000 == 0 {
		log.Printf("\n%v\n", a)
		log.Println(a.MTASTSTestingList)
		log.Println(a.MTASTSEnforceList)
	}

	if len(r.HostnameResults) == 0 {
		// No MX records - assume this isn't an email domain.
		return
	}
	a.WithMXs++
	if r.MTASTSResult != nil {
		switch r.MTASTSResult.Mode {
		case "enforce":
			a.MTASTSEnforceList = append(a.MTASTSEnforceList, r.Domain)
		case "testing":
			a.MTASTSTestingList = append(a.MTASTSTestingList, r.Domain)
		}
	}
}

func (a AggregatedScan) String() string {
	s := strings.Join([]string{"time", "source", "attempted", "with_mxs", "mta_sts_testing", "mta_sts_enforce"}, "\t") + "\n"
	s += fmt.Sprintf("%v\t%s\t%d\t%d\t%d\t%d\n", a.Time, a.Source, a.Attempted, a.WithMXs, len(a.MTASTSTestingList), len(a.MTASTSEnforceList))
	return s
}

// ResultHandler processes domain results.
// It could print them, aggregate them, write the to the db, etc.
type ResultHandler interface {
	HandleDomain(DomainResult)
}

const defaultPoolSize = 16

// CheckCSV runs the checker on a csv of domains, processing the results according
// to resultHandler.
func (c *Checker) CheckCSV(domains *csv.Reader, resultHandler ResultHandler, domainColumn int) {
	poolSize, err := strconv.Atoi(os.Getenv("CONNECTION_POOL_SIZE"))
	if err != nil || poolSize <= 0 {
		poolSize = defaultPoolSize
	}
	work := make(chan string)
	results := make(chan DomainResult)

	go func() {
		for {
			data, err := domains.Read()
			if err != nil {
				if err != io.EOF {
					log.Println("Error reading CSV")
					log.Fatal(err)
				}
				break
			}
			if len(data) > 0 {
				work <- data[domainColumn]
			}
		}
		close(work)
	}()

	done := make(chan struct{})
	for i := 0; i < poolSize; i++ {
		go func() {
			for domain := range work {
				results <- c.CheckDomain(domain, nil)
			}
			done <- struct{}{}
		}()
	}

	go func() {
		// Close the results channel when all the worker goroutines have finished.
		for i := 0; i < poolSize; i++ {
			<-done
		}
		close(results)
	}()

	for r := range results {
		resultHandler.HandleDomain(r)
	}
}
