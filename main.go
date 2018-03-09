package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "net"
    "os"
    "strings"
    "time"
    "encoding/json"
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
    run(chan CheckResult)
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

func generateFile(filename string, json bool) {
    fmt.Println("TO IMPLEMENT~")
}

func statusToString(status CheckStatus) string {
    if status == Success {
        return "SUCCESS"
    } else if status == Failure {
        return "FAILURE"
    } else if status == Error {
        return "ERROR"
    } else if status == Warning {
        return "WARNING"
    } else {
        return "NOT AVAILABLE"
    }
}

func performChecksFor(domain string, doMTASTSCheck bool, doSTARTTLSCheck bool) DomainReport {
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
        go check.run(done)
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

// Wrapper around performChecksFor that pipes result into a channel.
func performChecksForChan(domain string, doMTASTSCheck bool, doSTARTTLSCheck bool, done chan<- DomainReport) {
    done <- performChecksFor(domain, doMTASTSCheck, doSTARTTLSCheck)
}

// Perform a check on a particular domain, and time-out if it takse more than 20 seconds.
func domainCheckWorker(doMTASTSCheck bool, doSTARTTLSCheck bool, domains <-chan string, result chan<- DomainReport) {
    done := make(chan DomainReport)
    for domain := range domains {
        go performChecksForChan(domain, doMTASTSCheck, doSTARTTLSCheck, done)
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

// Performs checks for a set of domains.
// 16 worker threads performing these queries.
func performChecksForDomains(domains []string, doMTASTSCheck bool, doSTARTTLSCheck bool) map[string]DomainReport {
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
// Currently includes:
//  1. Checking for MTA-STS support.
//  2. Validating (START)TLS configurations for all MX domains.
//
// CLI arguments
// =============
//     -domain <domain> The domain to perform checks against.
//     -domains <file>  A file containing a list of domains to check.
//                      If specified, takes precedence over `domain` flag.
//   Checks
//     -mtasts          If set, will perform MTA-STS check.
//     -starttls        If set, will perform STARTTLS check.
//
//   NOTE: all checks are enabled by default. Setting any one
//   of these flags will disable all checks other than the ones
//   explicitly specified. For instance, the below two commands are
//   functionally equivalent:
//     ./starttls-check -domain example.com
//     ./starttls-check -domain example.com -mtasts -starttls
//   However, running:
//     ./starttls-check -domain example.com -starttls
//   will NOT perform any checks other than STARTTLS.
//
func main() {
    // 1. Setup and parse arguments.
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "\nNOTE: All checks are enabled by default. " +
                               "Setting any individual 'enable check' flag will disable "+
                               "all checks other than the ones explicitly specified.\n\n")
        fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
        flag.PrintDefaults()
    }
    domainStr := flag.String("domain", "", "Required: Domain to check TLS for.")
    domainsFileStr := flag.String("domains", "", "File containing domains to check TLS for.")
    jsonFlagPtr := flag.Bool("json", false, "Whether to generate policy as JSON file. If set, '-generate' flag should also be set.")
    generateFilePtr := flag.String("generate", "", "Where to output generated file.")
    doMTASTSCheckPtr := flag.Bool("mtasts", false, "Enable check for MTA-STS support.")
    doSTARTTLSCheckPtr := flag.Bool("starttls", false, "Enable check for STARTTLS support.")
    flag.Parse()
    if *domainStr == "" && *domainsFileStr == "" {
        flag.PrintDefaults()
        os.Exit(1)
    }
    doMTASTSCheck := true
    doSTARTTLSCheck := true
    if *doMTASTSCheckPtr || *doSTARTTLSCheckPtr {
        doMTASTSCheck = *doMTASTSCheckPtr
        doSTARTTLSCheck = *doSTARTTLSCheckPtr
    }

    if *domainsFileStr != "" {
        domains, err := domainsFromFile(*domainsFileStr)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Couldn't open file %s: %q", *domainsFileStr, err)
            os.Exit(1)
        }
        result := performChecksForDomains(domains, doMTASTSCheck, doSTARTTLSCheck)
        b, err := json.Marshal(result)
        if err != nil {
            fmt.Printf("%q", err)
        }
        fmt.Println(string(b))
    } else {
        result := performChecksFor(*domainStr, doMTASTSCheck, doSTARTTLSCheck)
b, err := json.Marshal(result)
        if err != nil {
            fmt.Printf("%q", err)
        }
        fmt.Println(string(b))

    }
    // If we were asked to generate a policy file, do it here.
    if len(*generateFilePtr) > 0 {
        generateFile(*generateFilePtr, *jsonFlagPtr)
    }
}
