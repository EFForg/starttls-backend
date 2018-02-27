package main

import (
    "io/ioutil"
    "fmt"
    "net"
    "net/http"
    "strings"
)

// Checks whether domain has MTA-STS support.
// Checks for:
// 1. MTA-STS TXT record in DNS.
// 2. TLSRPT TXT record in DNS.
// 3. Policy file exists at .well-known/mta-sts.txt endpoint.
// Each of these checks also ensures that the body found is well-formatted
// according to their relative IETF specifications.
type MTASTSCheck struct {
    Address string
    Reports []Report
}

// Helpers to report test results.

func (c *MTASTSCheck) reportError(message string) {
    c.Reports = append(c.Reports,
                       Report{ Message: fmt.Sprintf("  ERROR:   %s", message) })
}

func (c *MTASTSCheck) reportFailure(message string) {
    c.Reports = append(c.Reports,
                       Report{ Message: fmt.Sprintf("  FAILURE: %s", message) })
}

func (c *MTASTSCheck) reportSuccess(message string) {
    c.Reports = append(c.Reports,
                       Report{ Message: fmt.Sprintf("  SUCCESS: %s", message) })
}

// Retrieves all strings in |array| which have a specified prefix.
func withPrefix (array []string, prefix string) []string {
    filtered := []string{}
    for _, elem := range array {
        if elem[0:len(prefix)] == prefix {
            filtered = append(filtered, elem)
        }
    }
    return filtered
}

// Validates a set of records |records|. First, filters any records that do not
// have a given prefix-- then ensures that their fields are well-formed,
// according to |fields|.
func validateRecordWithFields(record string, fields map[string]enforceFunc,
                              lineDelimiter string, kvDelimiter string) error {
    // Assume format is (x=y;)*
    for _, line := range strings.Split(record, lineDelimiter) {
        if len(line) == 0 {
            continue
        }
        line = strings.TrimSpace(line)
        if !strings.Contains(line, kvDelimiter) {
            return fmt.Errorf("Malformed line '%s' does not contain " +
                              "delimiter %s", line, kvDelimiter)
        }
        split := strings.SplitN(line, kvDelimiter, 2)
        if f, ok := fields[split[0]]; ok {
            if (!f(strings.TrimSpace(split[1]))) {
                return fmt.Errorf("Field %s cannot have value %s",
                                  split[0], split[1])
            }
        } else {
            return fmt.Errorf("Field %s is unknown", split[0])
        }
    }
    return nil
}

// Enforcer functions for particular fields
type enforceFunc func(string) bool

func validSTSVersion (v string) bool {
    return v == "STSv1"
}

func validTLSRPTVersion (v string) bool {
    return v == "TLSRPTv1"
}

func validMode (v string) bool {
    return v == "enforce" || v == "testing" || v == "none"
}

func validNoop (v string) bool {
    return true
}

// |records| is a set of records returned by TXT lookup on DNS.
// There should only be one valid record.
//
// Returns error if:
//  - there does not exist exactly one valid TXT entry for TLSRPT.
//  - TXT record for TLSRPT is malformed
func validateMTASTSRecord (records []string) error {
    validFields := map[string]enforceFunc {"v": validSTSVersion ,
                                           "id": validNoop} // TODO: validate
    records = withPrefix(records, "v=STSv1;")
    if len(records) != 1 {
        return fmt.Errorf("There should exist exactly one TXT entry " +
                          "for MTA-STS.")
    }
    record := records[0]
    return validateRecordWithFields(record, validFields, ";", "=")
}

// |records| is a set of records returned by TXT lookup on DNS.
// There should only be one valid record.
//
// Returns error if:
//  - there does not exist exactly one valid TXT entry for TLSRPT.
//  - TXT record for TLSRPT is malformed
func validateTLSRPTRecord (records []string) error {
    validFields := map[string]enforceFunc {"v": validTLSRPTVersion ,
                                           "rua": validNoop} // TODO: validate
    records = withPrefix(records, "v=TLSRPTv1;")
    if len(records) != 1 {
        return fmt.Errorf("There should exist exactly one TXT entry " +
                          "for TLSRPT.")
    }
    record := records[0]
    return validateRecordWithFields(record, validFields, ";", "=")
}

// |body| is content of policy file.
// Returns error if policy file is malformed in some way.
func validatePolicyFile (body string) error {
    validFields := map[string]enforceFunc {"version": validSTSVersion,
                                           "mode": validMode,
                                           "mx": validNoop,      // TODO valid
                                           "max_age": validNoop} // TODO valid
    return validateRecordWithFields(body, validFields, "\n", ":")
}

// Perform all checks for MTA-STS.
// TODO: explicitly NAME each of these checks
func (c *MTASTSCheck) perform_checks() {
    // 1. CHECK: TXT record exists at _mta-sts
    results, err := net.LookupTXT(fmt.Sprintf("_mta-sts.%s", c.Address))
    if err != nil || len(results) == 0 {
        c.reportFailure(
            fmt.Sprintf("No TXT record found for _mta-sts.%s", c.Address))
    } else {
        // CHECK: MTA-STS TXT record well-formatted
        if err = validateMTASTSRecord(results); err == nil {
            c.reportSuccess(fmt.Sprintf("Fetched a valid MTA-STS TXT record."))
        } else {
            c.reportFailure(
                fmt.Sprintf("MTA-STS TXT record is not well-formed: %q", err))
        }
    }
    // 2. CHECK: TXT record exists at _smtp-tlsrpt
    results, err = net.LookupTXT(fmt.Sprintf("_smtp-tlsrpt.%s", c.Address))
    if err != nil {
        c.reportFailure(
            fmt.Sprintf("No TXT record found for _smtp-tlsrpt.%s", c.Address))
    } else {
        // CHECK: TLSRPT TXT record well-formatted
        if err = validateTLSRPTRecord(results); err == nil {
            c.reportSuccess(fmt.Sprintf("Fetched a valid TLSRPT TXT record."))
        } else {
            c.reportFailure(
                fmt.Sprintf("TLSRPT TXT record is not well-formed: %q", err))
        }
    }
    // 3. CHECK: 'mta-sts.<address>/.well-known/mta-sts.txt' exists
    policy_file, err := http.Get(fmt.Sprintf(
                            "https://mta-sts.%s/.well-known/mta-sts.txt",
                             c.Address))
    if err != nil {
        c.reportFailure(fmt.Sprintf("Could not fetch policy file from " +
                                     "mta-sts.%s/.well-known/mta-sts.txt",
                                     c.Address))
    } else {
        content, err := ioutil.ReadAll(policy_file.Body)
        if err != nil {
            c.reportError("Error reading policy file body.")
            return
        }
        // CHECK: MTA-STS policy file well-formatted
        if err = validatePolicyFile(string(content[:])); err == nil {
            c.reportSuccess(
                "Fetched valid policy file from /.well-known/mta-sts.txt")
        } else {
            c.reportFailure(
                fmt.Sprintf("Policy file is not well-formed: %q", err))
        }
    }
}

func (c MTASTSCheck) run(done chan CheckResult) {
    c.perform_checks()
    done <- CheckResult{
        title: fmt.Sprintf("=> MTA-STS Check for %s", c.Address),
        reports: c.Reports,
    }
}
