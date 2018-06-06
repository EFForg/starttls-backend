package checker

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// HostnameResult wraps the results of a security check against a particular hostname.
type HostnameResult struct {
	Domain      string                 `json:"domain"`
	Hostname    string                 `json:"hostname"`
	MxHostnames []string               `json:"mx_hostnames,omitempty"`
	Status      CheckStatus            `json:"status"`
	Checks      map[string]CheckResult `json:"checks"`
}

// Returns result of connectivity check. Should only be called after
// checkConnectivity. If called before that check occurs,
// returns false.
func (r HostnameResult) couldConnect() bool {
	if result, ok := r.Checks["connectivity"]; ok {
		return result.Status == Error
	}
	return false
}

// Modelled after isWildcardMatch in Appendix B of the MTA-STS draft.
// From draft v17:
// Senders who are comparing a "suffix" MX pattern with a wildcard
// identifier should thus strip the wildcard and ensure that the two
// sides match label-by-label, until all labels of the shorter side
// (if unequal length) are consumed.
func wildcardMatch(hostname string, pattern string) bool {
	if strings.HasPrefix(pattern, ".") {
		parts := strings.SplitAfterN(hostname, ".", 2)
		if len(parts) > 1 && parts[1] == pattern[1:] {
			return true
		}
	}
	return false
}

// Modelled after certMatches in Appendix B of the MTA-STS draft.
func policyMatch(certName string, policyMx string) bool {
	if strings.HasPrefix(certName, "*") {
		certName = certName[1:]
		if certName[0] != '.' { // Invalid wildcard domain
			return false
		}
	}
	return certName == policyMx || wildcardMatch(certName, policyMx) ||
		wildcardMatch(policyMx, certName)
}

// Checks certificate names against a list of expected MX patterns.
// The expected MX patterns are in the format described by MTA-STS,
// and validation is done according to this RFC as well.
func hasValidName(certNames []string, mxs []string) bool {
	for _, mx := range mxs {
		for _, certName := range certNames {
			if policyMatch(certName, mx) {
				return true
			}
		}
	}
	return false
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
func smtpDialWithTimeout(hostname string) (*smtp.Client, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:25", hostname), time.Second)
	if err != nil {
		return nil, err
	}
	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		return client, err
	}
	return client, client.Hello(getThisHostname())
}

// Performs a connectivity check.
func checkConnectivity(h HostnameResult) CheckResult {
	result := CheckResult{Name: "connectivity"}
	client, err := smtpDialWithTimeout(h.Hostname)
	if err != nil {
		return result.Error("Could not establish connection with hostname %s", h.Hostname)
	}
	defer client.Close()
	return result.Success()
}

// Simply tries to StartTLS with the server.
func checkStartTLS(h HostnameResult) CheckResult {
	result := CheckResult{Name: "starttls"}
	client, err := smtpDialWithTimeout(h.Hostname)
	if err != nil {
		return result.Error("Could not establish connection with hostname %s", h.Hostname)
	}
	defer client.Close()
	ok, _ := client.Extension("StartTLS")
	if !ok {
		return result.Failure("Server does not advertise support for STARTTLS.")
	}
	config := tls.Config{InsecureSkipVerify: true}
	err = client.StartTLS(&config)
	if err != nil {
		return result.Failure("Could not complete a TLS handshake.")
	}
	return result.Success()
}

// Retrieves valid names from certificate. If the certificate has
// SAN, retrieves all SAN domains; otherwise returns a list containing only the CN.
func getNamesFromCert(cert *x509.Certificate) []string {
	if cert.DNSNames != nil && len(cert.DNSNames) > 0 {
		return cert.DNSNames
	}
	return []string{cert.Subject.CommonName}
}

// If no MX matching policy was provided, then we'll default to accepting matches
// based on the mail domain and the MX hostname.
//
// Returns a list containing the domain and hostname.
func (h HostnameResult) defaultValidNames() []string {
	hostname := h.Hostname
	if strings.HasSuffix(hostname, ".") {
		hostname = hostname[0 : len(hostname)-1]
	}
	return []string{h.Domain, hostname}
}

// Validates that a certificate chain is valid for this system roots.
func verifyCertChain(state tls.ConnectionState) error {
	pool := x509.NewCertPool()
	for _, peerCert := range state.PeerCertificates[1:] {
		pool.AddCert(peerCert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         nil, // This ensures that the system roots are used.
		Intermediates: pool,
	})
	return err
}

// Checks that the certificate presented is valid for a particular hostname, unexpired,
// and chains to a trusted root.
func checkCert(h HostnameResult) CheckResult {
	result := CheckResult{Name: "certificate"}
	client, err := smtpDialWithTimeout(h.Hostname)
	if err != nil {
		return result.Error("Could not establish connection with hostname %s", h.Hostname)
	}
	defer client.Close()
	config := tls.Config{InsecureSkipVerify: true}
	err = client.StartTLS(&config)
	if err != nil {
		return result.Error("Could not start TLS: %v", err)
	}
	state, ok := client.TLSConnectionState()
	if !ok {
		return result.Error("TLS not initiated properly.")
	}
	cert := state.PeerCertificates[0]
	if h.MxHostnames == nil || len(h.MxHostnames) == 0 {
		h.MxHostnames = h.defaultValidNames()
	}
	if !hasValidName(getNamesFromCert(cert), h.MxHostnames) {
		result = result.Failure("Name in cert doesn't match any MX hostnames.")
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
func checkTLSCipher(h HostnameResult) CheckResult {
	result := CheckResult{Name: "cipher"}
	badCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}
	client, err := smtpDialWithTimeout(h.Hostname)
	if err != nil {
		return result.Error("Could not establish connection with hostname %s", h.Hostname)
	}
	defer client.Close()
	config := tlsConfigForCipher(badCiphers)
	err = client.StartTLS(&config)
	if err == nil {
		return result.Failure("Server should NOT be able to negotiate any ciphers with RC4.")
	}
	return result.Success()
}

func tlsConfigForVersion(version uint16) tls.Config {
	return tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}
}

// Transforms SSL/TLS constant into human-readable string
func versionToString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
		// case tls.VersionTLS13: return "TLSv1.3"
	}
	return "???"
}

// Checks to see that insecure versions of TLS cannot be negotiated.
func checkTLSVersion(h HostnameResult) CheckResult {
	result := CheckResult{Name: "version"}
	versions := map[uint16]bool{
		tls.VersionSSL30: false,
		tls.VersionTLS10: true,
		tls.VersionTLS11: true,
		tls.VersionTLS12: true,
	}
	for version, shouldWork := range versions {
		client, err := smtpDialWithTimeout(h.Hostname)
		if err != nil {
			return result.Error("Could not establish connection with hostname %s")
		}
		defer client.Close()
		config := tlsConfigForVersion(version)
		err = client.StartTLS(&config)
		if err != nil && shouldWork {
			result = result.Warning("Server should support %s, but doesn't.", versionToString(version))
		}
		if err == nil && !shouldWork {
			return result.Failure("Server should NOT support %s, but does.", versionToString(version))
		}
	}
	return result.Success()
}

// Wrapping helper function to set the status of this hostname.
func (h *HostnameResult) updateStatus(status CheckStatus) {
	h.Status = SetStatus(h.Status, status)
}

// CheckHostname performs a series of checks against a hostname for an email domain.
// `domain` is the mail domain that this server serves email for.
// `hostname` is the hostname for this server.
// `mxHostnames` is a list of MX patterns that `hostname` (and the associated TLS certificate)
//     can be valid for. If this is nil, then defaults to [`domain`, `hostname`].
func CheckHostname(domain string, hostname string, mxHostnames []string) HostnameResult {
	result := HostnameResult{
		Status:      Success,
		Domain:      domain,
		Hostname:    hostname,
		MxHostnames: mxHostnames,
		Checks:      make(map[string]CheckResult),
	}
	// 0. Perform connectivity sanity check.
	checkResult := checkConnectivity(result)
	result.Checks[checkResult.Name] = checkResult
	if checkResult.Status != Success {
		result.updateStatus(checkResult.Status)
		return result
	}
	// 1. Perform initial StartTLS check (and connectivity).
	//    If this fails, no other tests need to be performed.
	checkResult = checkStartTLS(result)
	result.Checks[checkResult.Name] = checkResult
	if checkResult.Status != Success {
		result.updateStatus(checkResult.Status)
		return result
	}
	// 2. Perform remainder of checks in parallel.
	results := make(chan CheckResult)
	go func() { results <- checkCert(result) }()
	go func() { results <- checkTLSCipher(result) }()
	go func() { results <- checkTLSVersion(result) }()
	for i := 0; i < 3; i++ {
		checkResult := <-results
		result.updateStatus(checkResult.Status)
		result.Checks[checkResult.Name] = checkResult
	}
	return result
}
