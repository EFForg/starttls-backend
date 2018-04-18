package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "os"
    "strings"
    "encoding/json"
    "github.com/sydneyli/starttls-check/checker"
)


func generateFile(filename string, json bool) {
    fmt.Println("TO IMPLEMENT~")
}

func statusToString(status checker.CheckStatus) string {
    if status == checker.Success {
        return "SUCCESS"
    } else if status == checker.Failure {
        return "FAILURE"
    } else if status == checker.Error {
        return "ERROR"
    } else if status == checker.Warning {
        return "WARNING"
    } else {
        return "NOT AVAILABLE"
    }
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
        result := checker.PerformChecksForDomains(domains, doMTASTSCheck, doSTARTTLSCheck)
        b, err := json.Marshal(result)
        if err != nil {
            fmt.Printf("%q", err)
        }
        fmt.Println(string(b))
    } else {
        result := checker.PerformChecksFor(*domainStr, doMTASTSCheck, doSTARTTLSCheck)
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
