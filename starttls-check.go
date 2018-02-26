package main

import (
    "flag"
    "os"
    "fmt"
    "net"
    "net/smtp"
    "crypto/tls"
)

type Report struct {
    Message string
}

type CheckResult struct {
    title string
    reports []Report
}

// Interface for particular Checks to run.
type Check interface {
    // Run this check. This function will be run in individual goroutines
    run(chan CheckResult)
    // A human-readable name for this check.
    title() string
}

// Checks port 25 on a particular domain for proper STARTTLS support.
// Checks for:
//  1. Connection check
//  2. STARTTLS Support
//  3. Valid certificates
//  4. TLS version up-to-date
//  5. Perfect forward secrecy
type StartTLSCheck struct {
    Address string
    Reports []Report
}

// type MTASTSCheck struct {
//     Address string
//     Reports []Report
// }


// Transforms SSL/TLS constant into human-readable string
func versionToString(version uint16) string {
    switch version {
        case tls.VersionSSL30: return "SSLv3"
        case tls.VersionTLS10: return "TLSv1.0"
        case tls.VersionTLS11: return "TLSv1.1"
        case tls.VersionTLS12: return "TLSv1.2"
        // case tls.VersionTLS13: return "TLSv1.3"
    }
    return "???"
}

// Returns True if SSL/TLS version is up-to-date.
// TODO: change this to be more fine-grained-- i.e. SSLv3 is 
//       worse than TLSv1.1, for instance.
func versionUpToDate(version uint16) bool {
    return version == tls.VersionTLS12
}

// Returns true if indicated cipher provides perfect forward secrecy.
func providesForwardSecrecy(cipher uint16) bool {
    return cipher > 0xc000
}

// Transforms cipher suite constant into human-readable string
func cipherToString(cipher uint16) string {
    switch cipher {
        case tls.TLS_RSA_WITH_RC4_128_SHA                : return "TLS_RSA_WITH_RC4_128_SHA"
        case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA           : return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        case tls.TLS_RSA_WITH_AES_128_CBC_SHA            : return "TLS_RSA_WITH_AES_128_CBC_SHA"
        case tls.TLS_RSA_WITH_AES_256_CBC_SHA            : return "TLS_RSA_WITH_AES_256_CBC_SHA"
        case tls.TLS_RSA_WITH_AES_128_CBC_SHA256         : return "TLS_RSA_WITH_AES_128_CBC_SHA256"
        case tls.TLS_RSA_WITH_AES_128_GCM_SHA256         : return "TLS_RSA_WITH_AES_128_GCM_SHA256"
        case tls.TLS_RSA_WITH_AES_256_GCM_SHA384         : return "TLS_RSA_WITH_AES_256_GCM_SHA384"
        case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        : return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
        case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    : return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
        case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    : return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
        case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA          : return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
        case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     : return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
        case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      : return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
        case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      : return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
        case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 : return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
        case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   : return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
        case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   : return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 : return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   : return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 : return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305    : return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
        case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  : return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
    }
    return "???"
}

// Helpers to report results of test.

func (c *StartTLSCheck) report_error(message string) {
    c.Reports = append(c.Reports, Report { Message: fmt.Sprintf("  ERROR:   %s", message) })
}

func (c *StartTLSCheck) report_failure(message string) {
    c.Reports = append(c.Reports, Report { Message: fmt.Sprintf("  FAILURE: %s", message) })
}

func (c *StartTLSCheck) report_success(message string) {
    c.Reports = append(c.Reports, Report { Message: fmt.Sprintf("  SUCCESS: %s", message) })
}

// Perform all checks for STARTTLS.
// TODO: explicitly NAME each of these checks, and enable/disable them through CLI flags.
func (c *StartTLSCheck) perform_checks() {
    // CHECK: Server connectivity
    client, err := smtp.Dial(fmt.Sprintf("%s:25", c.Address))
    if err != nil {
        c.report_error(fmt.Sprintf("Couldn't connect to address '%s'", c.Address))
        return
    }
    defer client.Close()

    // CHECK: STARTTLS Support
    ok, _ := client.Extension("StartTLS")
    if !ok {
        c.report_failure("Server does not advertise support for STARTTLS")
    }

    // Can we actually negotiate a TLS connection?
    // CHECK: Certificate validation
    config := &tls.Config{ ServerName: c.Address }
    err = client.StartTLS(config)
    if err != nil {
        // TODO: type-check on |err| to be more specific about failure
        c.report_failure(fmt.Sprintf("Server presented invalid certificate: %q", err))
        config = &tls.Config{ InsecureSkipVerify: true }
        // Reset connection and try again
        client.Close()
        client, _ = smtp.Dial(fmt.Sprintf("%s:25", c.Address))
        err = client.StartTLS(config)
        if err != nil {
            c.report_error("Could not establish TLS session at all.")
            return
        }
    } else {
        c.report_success("Valid certificate!")
    }

    state, ok := client.TLSConnectionState()
    if !ok {
        c.report_error("Could not retrieve TLS connection state" )
    }
    // CHECK: TLS version
    if versionUpToDate(state.Version) {
        c.report_success(fmt.Sprintf("TLS version up-to-date: %s", versionToString(state.Version)))
    } else {
        c.report_failure(fmt.Sprintf("TLS version outdated: %s", versionToString(state.Version)))
    }
    // CHECK: forward secrecy
    if providesForwardSecrecy(state.CipherSuite ) {
        c.report_success(fmt.Sprintf("Provides forward secrecy! (%s)", cipherToString(state.CipherSuite)))
    } else {
        c.report_failure(fmt.Sprintf("Cipher suite does not provide forward secrecy (%s)", cipherToString(state.CipherSuite)))
    }
}

func (c StartTLSCheck) title() string {
    return fmt.Sprintf("=> STARTTLS Check for %s", c.Address)
}

func (c StartTLSCheck) run(done chan CheckResult) {
    c.perform_checks()
    done <- CheckResult{
        title: c.title(),
        reports: c.Reports,
    }
}

// Transforms MX record's hostname into a regular domain address.
// In particular, absolute domains end with ".", so we can remove the dot.
func mxToAddr(mx string) string {
    if mx[len(mx)-1] == '.' {
        return mx[0:len(mx)-1]
    } else {
        return mx
    }
}

func main() {
    // Argument parsing.
    domainStr := flag.String("domain", "", "Domain to check TLS for.")
    flag.Parse()
    if *domainStr == "" {
        flag.PrintDefaults()
        os.Exit(1)
    }
    checks := []Check{}

    // MX record lookup.
    mxs, err := net.LookupMX(*domainStr)
    if err != nil {
        os.Exit(1)
    }
    for _, mx := range mxs {
        fmt.Println("MX:", mx.Host)
        checks = append(checks, StartTLSCheck{ Address: mxToAddr(mx.Host), Reports: []Report{} })
    }

    // Run checks for every domain from MX lookup!
    // Create callback channels
    var done = make(chan CheckResult)
    // Start running all the checks (async)
    for _, check := range checks {
        go check.run(done)
    }

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
