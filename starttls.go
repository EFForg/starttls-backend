package main

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

func (c *StartTLSCheck) reportError(message string) {
    c.Reports = append(c.Reports, Report { Message: fmt.Sprintf("  ERROR:   %s", message) })
}

func (c *StartTLSCheck) reportFailure(message string) {
    c.Reports = append(c.Reports, Report { Message: fmt.Sprintf("  FAILURE: %s", message) })
}

func (c *StartTLSCheck) reportSuccess(message string) {
    c.Reports = append(c.Reports, Report { Message: fmt.Sprintf("  SUCCESS: %s", message) })
}

// Perform all checks for STARTTLS.
// TODO: explicitly NAME each of these checks
func (c *StartTLSCheck) perform_checks() {
    // CHECK: Server connectivity
    client, err := smtp.Dial(fmt.Sprintf("%s:25", c.Address))
    if err != nil {
        c.reportError(fmt.Sprintf("Couldn't connect to address '%s'", c.Address))
        return
    }
    defer client.Close()

    // CHECK: STARTTLS Support
    ok, _ := client.Extension("StartTLS")
    if !ok {
        c.reportFailure("Server does not advertise support for STARTTLS")
    }

    // Can we actually negotiate a TLS connection?
    // CHECK: Certificate validation
    config := &tls.Config{ ServerName: c.Address }
    err = client.StartTLS(config)
    if err != nil {
        // TODO: type-check on |err| to be more specific about failure
        c.reportFailure(fmt.Sprintf("Server presented invalid certificate: %q", err))
        config = &tls.Config{ InsecureSkipVerify: true }
        // Reset connection and try again
        client.Close()
        client, _ = smtp.Dial(fmt.Sprintf("%s:25", c.Address))
        err = client.StartTLS(config)
        if err != nil {
            c.reportError("Could not establish TLS session at all.")
            return
        }
    } else {
        c.reportSuccess("Valid certificate!")
    }

    state, ok := client.TLSConnectionState()
    if !ok {
        c.reportError("Could not retrieve TLS connection state" )
    }
    // CHECK: TLS version
    if versionUpToDate(state.Version) {
        c.reportSuccess(fmt.Sprintf("TLS version up-to-date: %s",
                                    versionToString(state.Version)))
    } else {
        c.reportFailure(fmt.Sprintf("TLS version outdated: %s",
                                    versionToString(state.Version)))
    }
    // CHECK: forward secrecy
    if providesForwardSecrecy(state.CipherSuite ) {
        c.reportSuccess(fmt.Sprintf("Provides forward secrecy! (%s)",
                                    cipherToString(state.CipherSuite)))
    } else {
        c.reportFailure(fmt.Sprintf("Cipher suite does not provide forward secrecy (%s)",
                                    cipherToString(state.CipherSuite)))
    }
}

func (c StartTLSCheck) run(done chan CheckResult) {
    c.perform_checks()
    done <- CheckResult{
        title: fmt.Sprintf("=> STARTTLS Check for %s", c.Address),
        reports: c.Reports,
    }
}


