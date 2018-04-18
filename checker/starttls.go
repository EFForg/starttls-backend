package checker

import (
    "fmt"
    "net/smtp"
    "crypto/tls"
)

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

// TODO: classify RC4 and SHA1 as BAD!!!
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

func (c *StartTLSCheck) reportError(name string, message string) {
    c.Reports = append(c.Reports, Report { Message: message, Status: Error, Name: name })
}

func (c *StartTLSCheck) reportFailure(name string, message string) {
    c.Reports = append(c.Reports, Report { Message: message, Name: name, Status: Failure})
}

func (c *StartTLSCheck) reportSuccess(name string, message string) {
    c.Reports = append(c.Reports, Report { Message: message, Name: name, Status: Success })
}

func (c StartTLSCheck) getSubchecks() []string {
    return []string{"server_connectivity", "starttls", "certificate", "tls_version", "forward_secrecy"}
}


// Perform all checks for STARTTLS.
// TODO: explicitly NAME each of these checks
func (c *StartTLSCheck) perform_checks() {
    // CHECK: Server connectivity
    client, err := smtp.Dial(fmt.Sprintf("%s:25", c.Address))
    if err != nil {
        c.reportError("server_connectivity", fmt.Sprintf("Couldn't connect to address '%s'", c.Address))
        return
    }
    c.reportSuccess("server_connectivity", "")
    defer client.Close()

    // CHECK: STARTTLS Support
    ok, _ := client.Extension("StartTLS")
    if !ok {
        c.reportFailure("starttls", "Server does not advertise support for STARTTLS")
    } else {
        c.reportSuccess("starttls", "")
    }

    // Can we actually negotiate a TLS connection?
    // CHECK: Certificate validation
    config := &tls.Config{ ServerName: c.Address }
    err = client.StartTLS(config)
    if err != nil {
        // TODO: type-check on |err| to be more specific about failure
        c.reportFailure("certificate", fmt.Sprintf("Server presented invalid certificate: %q", err))
        // Reset connection and try again
        client.Close()
        config = &tls.Config{ InsecureSkipVerify: true }
        client, _ = smtp.Dial(fmt.Sprintf("%s:25", c.Address))
        err = client.StartTLS(config)
        if err != nil {
            c.reportError("starttls", "Could not establish TLS session at all.")
            return
        }
    } else {
        c.reportSuccess("certificate", c.Address)
    }

    state, ok := client.TLSConnectionState()
    if !ok {
        // This really shouldn't happen since we've already started TLS.
        c.reportError("starttls", "Could not retrieve TLS connection state" )
        return
    }
    // CHECK: TLS version
    if versionUpToDate(state.Version) {
        c.reportSuccess("tls_version", fmt.Sprintf("%s",
                                    versionToString(state.Version)))
    } else {
        c.reportFailure("tls_version", fmt.Sprintf("Outdated: %s",
                                    versionToString(state.Version)))
    }
    // CHECK: forward secrecy
    if providesForwardSecrecy(state.CipherSuite ) {
        c.reportSuccess("forward_secrecy", fmt.Sprintf("%s",
                                    cipherToString(state.CipherSuite)))
    } else {
        c.reportFailure("forward_secrecy", fmt.Sprintf("Cipher suite does not provide forward secrecy (%s)",
                                    cipherToString(state.CipherSuite)))
    }
}

func (c StartTLSCheck) Run(done chan CheckResult) {
    c.perform_checks()
    results := make(map[string]Report)
    for _, report := range c.Reports {
        results[report.Name] = report
    }
    for _, check := range c.getSubchecks() {
        if _, ok := results[check]; !ok {
            results[check] = Report { Name: check, Message: "Not performed.", Status: NotAvailable }
        }
    }
    done <- CheckResult{
        Title: "starttls",
        Address: c.Address,
        Reports: results,
    }
}


