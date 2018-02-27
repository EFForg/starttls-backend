package main

import (
    "flag"
    "fmt"
    "net"
    "os"
)

// A report (message) on a particular check.
// TODO: encode failure/success state in this struct
type Report struct {
    Message string
}

// The results of running a suite of checks.
type CheckResult struct {
    title string        // A human-readable title for this check suite.
    reports []Report    // List of reports generated from these checks.
}


// Interface for running a particular suite of Checks.
type Check interface {
    // Run this check. This function is run in individual goroutines.
    // When finisehd, a CheckResult should be passed into the given channel.
    run(chan CheckResult)
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

//
// Run a series of security checks on an MTA domain.
// =================================================
// Currently includes:
//  1. Checking for MTA-STS support.
//  2. Validating (START)TLS configurations for all MX domains.
//
// CLI arguments
// =============
//   Required 
//     -domain <domain> The domain to perform checks against.
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
    doMTASTSCheckPtr := flag.Bool("mtasts", false, "Enable check for MTA-STS support.")
    doSTARTTLSCheckPtr := flag.Bool("starttls", false, "Enable check for STARTTLS support.")
    flag.Parse()
    if *domainStr == "" {
        flag.PrintDefaults()
        os.Exit(1)
    }
    doMTASTSCheck := true
    doSTARTTLSCheck := true
    if *doMTASTSCheckPtr || *doSTARTTLSCheckPtr {
        doMTASTSCheck = *doMTASTSCheckPtr
        doSTARTTLSCheck = *doSTARTTLSCheckPtr
    }
    checks := []Check{}

    // 2. Add MTASTS check.
    if doMTASTSCheck {
        checks = append(checks, MTASTSCheck{ Address: *domainStr, Reports: []Report{} })
    }

    // 3. Add STARTTLS checks (for each MX record!)
    if doSTARTTLSCheck {
        // 3a. MX record lookup.
        mxs, err := net.LookupMX(*domainStr)
        if err != nil {
            os.Exit(1)
        }
        // 3b. Add STARTTLS checks.
        for _, mx := range mxs {
            fmt.Println("MX:", mx.Host)
            checks = append(checks, StartTLSCheck{ Address: mxToAddr(mx.Host), Reports: []Report{} })
        }
    }

    // 4. Run all checks (async)
    var done = make(chan CheckResult)
    for _, check := range checks {
        go check.run(done)
    }

    // 5. Output check results.
    i := 0
    for i < len(checks) {
        results := <-done
        fmt.Println(results.title)
        for _, result := range results.reports {
            fmt.Println(result.Message)
        }
        i += 1
    }
}

