package checker

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// HostnameResult wraps the results of a security check against a particular hostname.
type HostnameResult struct {
	*Result
	Domain    string    `json:"domain"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"-"`
}

// Returns result of specified check.
// If called before that check occurs, returns false.
func (h HostnameResult) checkSucceeded(checkName string) bool {
	if result, ok := h.Checks[checkName]; ok {
		return result.Status == Success
	}
	return false
}

func (h HostnameResult) couldConnect() bool {
	return h.checkSucceeded("connectivity")
}

func (h HostnameResult) couldSTARTTLS() bool {
	return h.checkSucceeded("starttls")
}

// Modelled after policyMatches in Appendix B of the MTA-STS RFC 8641.
// Also used to validate hostnames on the STARTTLS Everywhere policy list.
func policyMatches(mx string, patterns []string) bool {
	mx = strings.TrimSuffix(mx, ".") // If FQDN, might end with .
	mx = withoutPort(mx)             // If URL, might include port
	mx = strings.ToLower(mx)         // Lowercase for comparison
	for _, pattern := range patterns {
		pattern = strings.ToLower(pattern)

		// Literal match
		if pattern == mx {
			return true
		}
		// Wildcard match
		if strings.HasPrefix(pattern, "*.") || strings.HasPrefix(pattern, ".") {
			pattern = strings.TrimPrefix(pattern, "*")
			mxParts := strings.SplitN(mx, ".", 2)
			if len(mxParts) > 1 && mxParts[1] == pattern[1:] {
				return true
			}
		}
	}
	return false
}

func withoutPort(url string) string {
	if strings.Contains(url, ":") {
		return url[0:strings.LastIndex(url, ":")]
	}
	return url
}

// Retrieves this machine's hostname, if specified.
func getThisHostname() string {
	hostname := os.Getenv("HOSTNAME")
	if len(hostname) == 0 {
		return "localhost"
	}
	return hostname
}

// Performs an SMTP dial with a short timeout.
// https://github.com/golang/go/issues/16436
func smtpDialWithTimeout(hostname string, timeout time.Duration) (*smtp.Client, error) {
	if _, _, err := net.SplitHostPort(hostname); err != nil {
		hostname += ":25"
	}
	conn, err := net.DialTimeout("tcp", hostname, timeout)
	if err != nil {
		return nil, err
	}
	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		return client, err
	}
	return client, client.Hello(getThisHostname())
}

// Simply tries to StartTLS with the server.
func checkStartTLS(client *smtp.Client) *Result {
	result := MakeResult(STARTTLS)
	ok, _ := client.Extension("StartTLS")
	if !ok {
		return result.Failure("Server does not advertise support for STARTTLS.")
	}
	config := tls.Config{InsecureSkipVerify: true}
	if err := client.StartTLS(&config); err != nil {
		return result.Failure("Could not complete a TLS handshake.")
	}
	return result.Success()
}

// If no MX matching policy was provided, then we'll default to accepting matches
// based on the mail domain and the MX hostname.
//
// Returns a list containing the domain and hostname.
func defaultValidMX(domain, hostname string) []string {
	if strings.HasSuffix(hostname, ".") {
		hostname = hostname[0 : len(hostname)-1]
	}
	return []string{domain, hostname}
}

// Validates that a certificate chain is valid for this system roots.
func verifyCertChain(state tls.ConnectionState) error {
	pool := x509.NewCertPool()
	for _, peerCert := range state.PeerCertificates[1:] {
		pool.AddCert(peerCert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         certRoots,
		Intermediates: pool,
	})
	return err
}

// certRoots is the certificate roots to use for verifying
// a TLS certificate. It is nil by default so that the system
// root certs are used.
//
// It is a global variable because it is used as a test hook.
var certRoots *x509.CertPool

// Checks that the certificate presented is valid for a particular hostname, unexpired,
// and chains to a trusted root.
func checkCert(client *smtp.Client, domain, hostname string) *Result {
	result := MakeResult(Certificate)
	state, ok := client.TLSConnectionState()
	if !ok {
		return result.Error("TLS not initiated properly.")
	}
	cert := state.PeerCertificates[0]
	// If hostname is an FQDN, it might end with '.'
	hostname = strings.TrimSuffix(hostname, ".")
	err := cert.VerifyHostname(withoutPort(hostname))
	if err != nil {
		result.Failure("Name in cert doesn't match hostname: %v", err)
	}
	err = verifyCertChain(state)
	if err != nil {
		return result.Failure("Certificate root is not trusted: %v", err)
	}
	return result.Success()
}

func tlsConfigForCipher(ciphers []uint16) tls.Config {
	return tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       ciphers,
	}
}

// Checks to see that insecure ciphers are disabled.
func checkTLSCipher(hostname string, timeout time.Duration) *Result {
	result := MakeResult(CheckType{Name: "cipher"})
	badCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}
	client, err := smtpDialWithTimeout(hostname, timeout)
	if err != nil {
		return result.Error("Could not establish connection with hostname %s", hostname)
	}
	defer client.Close()
	config := tlsConfigForCipher(badCiphers)
	err = client.StartTLS(&config)
	if err == nil {
		return result.Failure("Server should NOT be able to negotiate any ciphers with RC4.")
	}
	return result.Success()
}

func checkTLSVersion(client *smtp.Client, hostname string, timeout time.Duration) *Result {
	result := MakeResult(Version)

	// Check the TLS version of the existing connection.
	tlsConnectionState, ok := client.TLSConnectionState()
	if !ok {
		// We shouldn't end up here because we already checked that STARTTLS succeeded.
		return result.Error("Could not check TLS connection version.")
	}
	if tlsConnectionState.Version < tls.VersionTLS12 {
		result = result.Warning("Server should support TLSv1.2, but doesn't.")
	}

	// Attempt to connect with an old SSL version.
	client, err := smtpDialWithTimeout(hostname, timeout)
	if err != nil {
		return result.Error("Could not establish connection: %v", err)
	}
	defer client.Close()
	config := tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionSSL30,
	}
	err = client.StartTLS(&config)
	if err == nil {
		return result.Failure("Server should NOT support SSLv2/3, but does.")
	}
	return result.Success()
}

// CheckHostname performs a series of checks against a hostname for an email domain.
// `domain` is the mail domain that this server serves email for.
// `hostname` is the hostname for this server.
func (c *Checker) CheckHostname(domain string, hostname string) HostnameResult {
	if c.checkHostname != nil {
		// Allow the Checker to mock this function.
		return c.checkHostname(domain, hostname)
	}

	result := HostnameResult{
		Domain:    domain,
		Hostname:  hostname,
		Result:    MakeResult(CheckType{Name: "hostname"}),
		Timestamp: time.Now(),
	}

	// Connect to the SMTP server and use that connection to perform as many checks as possible.
	connectivityResult := MakeResult(Connectivity)
	client, err := smtpDialWithTimeout(hostname, c.timeout())
	if err != nil {
		result.addCheck(connectivityResult.Error("Could not establish connection: %v", err))
		return result
	}
	defer client.Close()
	result.addCheck(connectivityResult.Success())

	result.addCheck(checkStartTLS(client))
	if result.Status != Success {
		return result
	}
	result.addCheck(checkCert(client, domain, hostname))
	// result.addCheck(checkTLSCipher(hostname))

	// Creates a new connection to check for SSLv2/3 support because we can't call starttls twice.
	result.addCheck(checkTLSVersion(client, hostname, c.timeout()))

	return result
}

// Supported checks against hostnames
var (
	STARTTLS CheckType = CheckType{
		Name: "starttls",
		StatusText: StatusText{
			Success: "Supports STTARTTLS",
			Failure: "Does not support STARTTLS",
		},
		Description: `“STARTTLS” is the command an email server sends if it wants to encrypt communications (using Transport Layer Security or “TLS”) with another email server. If your server supports STARTTLS, that means any other server that supports STARTTLS can communicate securely with it.

This checks that your email server sends the STARTTLS command correctly, as well as accepting the STARTTLS command from other servers.`,
	}
	Version CheckType = CheckType{
		Name: "version",
		StatusText: StatusText{
			Success: "Uses a secure version of TLS",
			Failure: "Does not use a secure TLS version",
		},
		Description: `TLS has changed many times over the years. Researchers have discovered security flaws in some older versions, named “SSLv2” and “SSLv3”, so technologists across the internet are <a href="https://disablessl3.com/" target="_blank">working to deprecate</a> SSLv2/3.

This checks that your email server does not allow establishing a valid TLS connection over SSLv2/3.`,
	}
	Certificate CheckType = CheckType{
		Name: "certificate",
		StatusText: StatusText{
			Success: "Presents a valid certificate",
			Failure: "Does not present a valid certificate",
		},
		Description: `On the internet, even if you *think* you’re talking to a service named “eff.org”, it could be an impersonator pretending to be “eff.org”. Checking a mail server’s certificate helps ensure that you really are talking to the actual service.

In order for your certificate to be valid for your email domain, it should be unexpired, chain to a <a href="https://wiki.mozilla.org/CA/Included_Certificates" target="_blank">valid root</a>, and one of the names on the certificate should either match the domain (the part of an email address after the @) or the server’s hostname (the name of the server, as indicated by an MX record).`,
	}
	Connectivity CheckType = CheckType{
		Name: "connectivity",
		StatusText: StatusText{
			Success: "Server is up and running",
			Failure: "Could not establish connection",
		},
		Description: `We couldn't successfully connect to this mailserver to scan it. This could be an error on our side, too. If you're having trouble getting the scanner to work, shoot us an email at <a href="mailto:starttls-policy@eff.org">starttls-policy@eff.org</a>.`,
	}
)
