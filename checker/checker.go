package checker

import (
    "fmt"
    "net"
    "encoding/json"
    "time"
)

type CheckStatus int32
const (
    Success      = 0
    Warning      = 1
    Failure      = 2
    Error        = 3 // Some check failed.
    NotAvailable = 4 // Due to earlier check error/failure.
)

// A report (message) on a particular check.
type Report struct {
    Name string
    Message string
    Status CheckStatus
}

// The results of running a suite of checks.
type CheckResult struct {
    Title string        // A human-readable title for this check suite.
    Address string
    Reports map[string]Report
    // reports []Report    // List of reports generated from these checks.
}

// Interface for running a particular suite of Checks.
type Check interface {
    // Run this check. This function is run in individual goroutines.
    // When finisehd, a CheckResult should be passed into the given channel.
    Run(chan CheckResult)
    // Returns the Subchecks in the order that they are performed!
    getSubchecks() []string
}

type DomainReport struct {
    Domain string
    CheckResults map[string]CheckResult
}

// Helper to transforms MX record's hostname into a regular domain address.
// In particular, absolute domains end with ".", so we can remove the dot.
func mxToAddr(mx string) string {
    if mx[len(mx)-1] == '.' {
        return mx[0:len(mx)-1]
    } else {
        return mx
    }
}

func PerformChecksJSON(domain string, doMTASTSCheck bool, doSTARTTLSCheck bool) (string, error) {
    report := PerformChecksFor(domain, doMTASTSCheck, doSTARTTLSCheck)
    b, err := json.Marshal(report)
    if err != nil {
        return "", err
    }
    return string(b), nil
}

func PerformChecksFor(domain string, doMTASTSCheck bool, doSTARTTLSCheck bool) DomainReport {
    fmt.Printf("Checking %s\n", domain)
    checks := []Check{}

    // 1. Add MTASTS check.
    if doMTASTSCheck {
        checks = append(checks, MTASTSCheck{ Address: domain, Reports: []Report{} })
    }

    // 2. Add STARTTLS checks (for each MX record!)
    mx_addrs := []string{}
    if doSTARTTLSCheck {
        // 2a. MX record lookup.
        mxs, err := net.LookupMX(domain)
        if err != nil || len(mxs) == 0 {
            fmt.Printf("No MX records found for domain %s!\n", domain)
            return DomainReport {
                Domain: domain,
                CheckResults: make(map[string]CheckResult),
            }
        } else {
        // 2b. Add STARTTLS checks.
        //     Only adds for top-preference domain. TODO: for individual e-mail scans should
        //     perform check for *all* domains.
        mx_addrs = append(mx_addrs, mxToAddr(mxs[0].Host))
        checks = append(checks, StartTLSCheck{ Address: mxToAddr(mxs[0].Host), Reports: []Report{} })
        // for _, mx := range mxs {
        //     mx_addrs = append(mx_addrs, mxToAddr(mx.Host))
        //     checks = append(checks, StartTLSCheck{ Address: mxToAddr(mx.Host), Reports: []Report{} })
        // }
        }
    }

    // 3. Run all checks (async)
    var done = make(chan CheckResult)
    for _, check := range checks {
        go check.Run(done)
    }

    report := DomainReport {
        Domain: domain,
        CheckResults: make(map[string]CheckResult),
    }

    // 4. Output check results.
    i := 0
    for i < len(checks) {
        results := <-done
        // fmt.Println(results.title)
        report.CheckResults[results.Title] = results
        // for _, result := range results.reports {
        //     fmt.Println(fmt.Sprintf("  %s:%s; %s", statusToString(result.Status), result.Name, result.Message))
        // }
        i += 1
    }
    return report
}

// Perform a check on a particular domain, and time-out if it takse more than 20 seconds.
func domainCheckWorker(doMTASTSCheck bool, doSTARTTLSCheck bool, domains <-chan string, result chan<- DomainReport) {
    done := make(chan DomainReport)
    for domain := range domains {
        go PerformChecksForChan(domain, doMTASTSCheck, doSTARTTLSCheck, done)
        select {
            case ret := <-done:
                result <- ret
            case <-time.After(20 * time.Second):
                fmt.Printf("TIMED out checking %s\n", domain)
                result <- DomainReport {
                    Domain: domain,
                    CheckResults: make(map[string]CheckResult),
                }
        }
    }
}


// Wrapper around performChecksFor that pipes result into a channel.
func PerformChecksForChan(domain string, doMTASTSCheck bool, doSTARTTLSCheck bool, done chan<- DomainReport) {
    done <- PerformChecksFor(domain, doMTASTSCheck, doSTARTTLSCheck)
}

// Performs checks for a set of domains.
// 16 worker threads performing these queries.
func PerformChecksForDomains(domains []string, doMTASTSCheck bool, doSTARTTLSCheck bool) map[string]DomainReport {
    poolSize := 16
    jobs := make(chan string, 100)
    results := make(chan DomainReport, 100)
    domainResults := make(map[string]DomainReport)
    for worker := 1; worker <= poolSize; worker++ {
        go domainCheckWorker(doMTASTSCheck, doSTARTTLSCheck, jobs, results)
    }
    for _, domain := range domains {
        jobs <- domain
    }
    close(jobs)
    for i := 0; i < len(domains); i++ {
        result := <-results
        domainResults[result.Domain] = result
        b, err := json.Marshal(result)
        if err != nil {
            fmt.Printf("%q", err)
        } else {
            fmt.Println(string(b))
        }
    }
    return domainResults
}


