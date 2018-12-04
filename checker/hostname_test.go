package checker

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mhale/smtpd"
)

func TestMain(m *testing.M) {
	certString = createCert(key, "localhost")
	certStringHostnameMismatch = createCert(key, "you_give_love_a_bad_name")
	code := m.Run()
	os.Exit(code)
}

const testTimeout = 250 * time.Millisecond

// Code follows pattern from crypto/tls/generate_cert.go
// to generate a cert from a PEM-encoded RSA private key.
func createCert(keyData string, commonName string) string {
	// 1. Convert privkey from PEM to DER.
	block, _ := pem.Decode([]byte(key))
	privKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	// 2. Generate cert with private key.
	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute),
		IsCA:         true,
		DNSNames:     []string{commonName},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &(privKey.PublicKey), privKey)
	// 3. Convert cert to PEM format (for consumption by crypto/tls)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM := pem.EncodeToMemory(&b)
	return string(certPEM)
}

func TestPolicyMatch(t *testing.T) {
	var tests = []struct {
		certName string
		policyMX string
		want     bool
	}{
		// Equal matches
		{"example.com", "example.com", true},
		{"mx.example.com", "mx.example.com", true},

		// Not equal matches
		{"different.org", "example.com", false},
		{"not.example.com", "example.com", false},

		// base domain shouldn't match wildcard
		{"example.com", ".example.com", false},
		{"*.example.com", "example.com", false},

		// Invalid wildcard shouldn't match.
		{"*mx.example.com", "mx.example.com", false},

		// Single-level subdomain match for policy suffix.
		{"mx.example.com", ".example.com", true},
		{"*.example.com", ".example.com", true},

		// No multi-level subdomain matching for policy suffix.
		{"mx.mx.example.com", ".example.com", false},
		{"*.mx.example.com", ".example.com", false},

		// Role reversal also works.
		{"*.example.com", "mx.example.com", true},
		{"*.example.com", "mx.mx.example.com", false},
		{"*.example.com", ".mx.example.com", false},
	}

	for _, test := range tests {
		if got := policyMatch(test.certName, test.policyMX); got != test.want {
			t.Errorf("policyMatch(%q, %q) = %v", test.certName, test.policyMX, got)
		}
	}
}

func TestNoConnection(t *testing.T) {
	result := CheckHostname("", "example.com", testTimeout)

	expected := HostnameResult{
		Status: 3,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 3, nil},
		},
	}
	compareStatuses(t, expected, result)
}

func TestNoTLS(t *testing.T) {
	ln := smtpListenAndServe(t, &tls.Config{})
	defer ln.Close()

	result := CheckHostname("", ln.Addr().String(), testTimeout)

	expected := HostnameResult{
		Status: 2,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 0, nil},
			"starttls":     {"starttls", 2, nil},
		},
	}
	compareStatuses(t, expected, result)
}

func TestSelfSigned(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(certString), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	ln := smtpListenAndServe(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer ln.Close()

	result := CheckHostname("", ln.Addr().String(), testTimeout)

	expected := HostnameResult{
		Status: 2,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 0, nil},
			"starttls":     {"starttls", 0, nil},
			"certificate":  {"certificate", 2, nil},
			"version":      {"version", 0, nil},
		},
	}
	compareStatuses(t, expected, result)
}

func TestNoTLS12(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(certString), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	ln := smtpListenAndServe(t, &tls.Config{
		MinVersion:   tls.VersionTLS11,
		MaxVersion:   tls.VersionTLS11,
		Certificates: []tls.Certificate{cert},
	})
	defer ln.Close()

	result := CheckHostname("", ln.Addr().String(), testTimeout)

	expected := HostnameResult{
		Status: 2,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 0, nil},
			"starttls":     {"starttls", 0, nil},
			"certificate":  {"certificate", 2, nil},
			"version":      {"version", 1, nil},
		},
	}
	compareStatuses(t, expected, result)
}

func TestSuccessWithFakeCA(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(certString), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	ln := smtpListenAndServe(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer ln.Close()

	certRoots, _ = x509.SystemCertPool()
	certRoots.AppendCertsFromPEM([]byte(certString))
	defer func() {
		certRoots = nil
	}()

	// Our test cert happens to be valid for hostname "localhost",
	// so here we replace the loopback address with "localhost" while
	// conserving the port number.
	addrParts := strings.Split(ln.Addr().String(), ":")
	port := addrParts[len(addrParts)-1]
	result := CheckHostname("", "localhost:"+port, testTimeout)
	expected := HostnameResult{
		Status: 0,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 0, nil},
			"starttls":     {"starttls", 0, nil},
			"certificate":  {"certificate", 0, nil},
			"version":      {"version", 0, nil},
		},
	}
	compareStatuses(t, expected, result)
}

// Tests that the checker successfully initiates an SMTP connection with mail
// servers that use a greet delay.
func TestSuccessWithDelayedGreeting(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeDelayedGreeting(ln, t)

	client, err := smtpDialWithTimeout(ln.Addr().String(), testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
}

func ServeDelayedGreeting(ln net.Listener, t *testing.T) {
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	time.Sleep(testTimeout + 100*time.Millisecond)
	_, err = conn.Write([]byte("220 localhost ESMTP\n"))
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "EHLO localhost") {
		t.Fatalf("unexpected response from checker: %s", line)
	}

	_, err = conn.Write([]byte("250 HELO\n"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestFailureWithBadHostname(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(certString), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	ln := smtpListenAndServe(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer ln.Close()

	certRoots, _ = x509.SystemCertPool()
	certRoots.AppendCertsFromPEM([]byte(certStringHostnameMismatch))
	defer func() {
		certRoots = nil
	}()

	// Our test cert happens to be valid for hostname "localhost",
	// so here we replace the loopback address with "localhost" while
	// conserving the port number.
	addrParts := strings.Split(ln.Addr().String(), ":")
	port := addrParts[len(addrParts)-1]
	result := CheckHostname("", "localhost:"+port, testTimeout)
	expected := HostnameResult{
		Status: 2,
		Checks: map[string]CheckResult{
			"connectivity": {"connectivity", 0, nil},
			"starttls":     {"starttls", 0, nil},
			"certificate":  {"certificate", 2, nil},
			"version":      {"version", 0, nil},
		},
	}
	compareStatuses(t, expected, result)
}

func TestAdvertisedCiphers(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(certString), []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	var cipherSuites []uint16
	// GetConfigForClient is a callback that lets us alter the TLSConfig
	// based on the client hello. Here we just use it to check which ciphers
	// are advertised by the client.
	//
	// Alternatively, we could use the CipherSuites attribute to attempt a
	// separate connection with each cipher.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			if len(cipherSuites) == 0 {
				// Throw out the second connection to the mailserver
				// where we intentionally advertised insecure ciphers.
				cipherSuites = info.CipherSuites
			}
			return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
		},
	}

	ln := smtpListenAndServe(t, tlsConfig)
	defer ln.Close()
	CheckHostname("", ln.Addr().String(), testTimeout)

	// Partial list of ciphers we want to support
	expectedCipherSuites := []struct {
		val  uint16
		desc string
	}{
		{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"},
	}
	for _, expected := range expectedCipherSuites {
		if !containsCipherSuite(cipherSuites, expected.val) {
			t.Errorf("expected check to advertise ciphersuite %s", expected.desc)
		}
	}
}

func containsCipherSuite(result []uint16, want uint16) bool {
	for _, candidate := range result {
		if want == candidate {
			return true
		}
	}
	return false
}

// compareStatuses compares the status for the HostnameResult and each Check with a desired value
func compareStatuses(t *testing.T, expected HostnameResult, result HostnameResult) {
	if result.Status != expected.Status {
		t.Errorf("hostname status = %d, want %d", result.Status, expected.Status)
	}

	if len(result.Checks) > len(expected.Checks) {
		t.Errorf("result contains too many checks\n expected %v\n want %v", result.Checks, expected.Checks)
	}

	for _, c := range expected.Checks {
		if got := result.Checks[c.Name].Status; got != c.Status {
			t.Errorf("%s status = %d, want %d", c.Name, got, c.Status)
		}
	}
}

// smtpListenAndServe creates a test smtp server to run checks on.
// We use this rather than smtpd.ListenAndServe so that we can use net.Listen
// to assign a random available port.
func smtpListenAndServe(t *testing.T, tlsConfig *tls.Config) net.Listener {
	srv := &smtpd.Server{
		Handler:  noopHandler,
		Hostname: "example.com",
	}
	srv.TLSConfig = tlsConfig

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := srv.Serve(ln); err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			t.Fatal(err)
		}
	}()

	return ln
}

func noopHandler(_ net.Addr, _ string, _ []string, _ []byte) {}

var certString string
var certStringHostnameMismatch string

const key = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC7BhTtrZkgD7Q0fGHHBl4TRrEFO2KmN93MVZdTob2S3nwWsFUo
aP9Jx4WsQ0F+MwP2nKTS52LvTCqPyD9VFp9XS52Mtq6cylK+UTkKAQnSVu14g5dS
0gAbM914zxO1NFp/9C4iCi0qaKWzPCGLCIEoqkb7+HlYQekBkJHR3Tzq3QIDAQAB
AoGBALL2RuCI1ZYQcOgofYftV+gqJQpUoTldDCiTXpLwmm8H5sXvRg29K0x2WDtW
wDz6pDg//Ji0Qb+qqq+bdr79PsquUon6G+t9LWFQ6F1qD7JRssBr5FPAfWFij2pm
zH61dX/j/kas67W+23H4k0Rc3oExaPF4gecc/EJaQ4Wc5EohAkEA6GaMhlwsONhv
TbW3FIOm54obvLhS0XDrdig8CIl7+x6KSBsHBmLv+MDh/DRywwv5sOR6Sg6HGMAc
4pNsk6UOXwJBAM4D7HHfqMyuiKDIiAwdjPn/Ux2nlQe05d7iai0nSEVEfneaGX/g
r4C1Gg8VDA6U94XE/S9d60IpUg4DwH9W2EMCQCufxFUcTDjHd+0wZRN2uwfPhvFf
8DvcZHajitFXbWxwCSkL2b+7JqydGE6NUdWHE/G+ka4BGB7vQPzPC5yTaSUCQAn3
Ap7XdLDB2HX+fSYo38LP6NNMYdcHlv7a8MvSVJqVH5DlcUpQMe0F1YbZO8YQypA7
4QtDfberi/6Fi/Ac4UUCQQDHf89gtZYZKfeTBMRwaer7yG/UovX2AJSkCB34BGxn
gIxzlen/RRmXtBGCR5G24n08/2AJaMeI/8sJWM8or9cs
-----END RSA PRIVATE KEY-----`
