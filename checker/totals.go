package checker

import (
	"encoding/csv"
	"io"
	"log"
	"time"
)

// DomainTotals compiled aggregated stats across domains.
// Implements ResultHandler.
type DomainTotals struct {
	Time          time.Time
	Source        string
	Attempted     int
	Connected     int // Connected to at least one mx
	MTASTSTesting int
	MTASTSEnforce int
}

// Add the result of a single domain check to aggregated stats.
func (t *DomainTotals) HandleDomain(r DomainResult) {
	t.Attempted += 1
	// If DomainStatus is > 4, we couldn't connect to a mailbox.
	if r.Status > 4 {
		return
	}
	t.Connected += 1
	if r.MTASTSResult != nil {
		switch r.MTASTSResult.Mode {
		case "enforce":
			t.MTASTSEnforce += 1
		case "testing":
			t.MTASTSTesting += 1
		}
	}
}

// ResultHandler processes domain results.
// It could print them, aggregate them, write the to the db, etc.
type ResultHandler interface {
	HandleDomain(DomainResult)
}

const poolSize = 16

// CheckList runs checks on a list of domains, processing the results according
// to resultHandler.
func (c *Checker) CheckCSV(domains *csv.Reader, resultHandler ResultHandler) {
	work := make(chan string)
	results := make(chan DomainResult)

	go func() {
		for {
			data, err := domains.Read()
			if err != nil {
				if err != io.EOF {
					log.Fatal(err)
				}
				break
			}
			if len(data) > 0 {
				work <- data[0]
			}
		}
		close(work)
	}()

	done := make(chan struct{}, poolSize)
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
