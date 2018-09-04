package checker

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/mhale/smtpd"
)

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
	result := CheckHostname("", "example.com")

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

	result := CheckHostname("", ln.Addr().String())

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

	result := CheckHostname("", ln.Addr().String())

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

	result := CheckHostname("", ln.Addr().String())

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
	result := CheckHostname("", "localhost:"+port)
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
	result := CheckHostname("", "localhost:"+port)
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
	CheckHostname("", ln.Addr().String())

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

// Commands to generate the self-signed certificates below:
//	openssl req -new -key server.key -out server.csr
//	openssl x509 -req -in server.csr -signkey server.key -out server.crt
// certString was created with a CN of "localhost"; certStringHostnameMismatch
// has an empty/no CN.

const certString = `-----BEGIN CERTIFICATE-----
MIICKTCCAZICCQDPUsAOcVJx1jANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJB
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTgwODIzMTkxOTA5WhcN
MTgwOTIyMTkxOTA5WjBZMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0
ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDDAls
b2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALsGFO2tmSAPtDR8
YccGXhNGsQU7YqY33cxVl1OhvZLefBawVSho/0nHhaxDQX4zA/acpNLnYu9MKo/I
P1UWn1dLnYy2rpzKUr5ROQoBCdJW7XiDl1LSABsz3XjPE7U0Wn/0LiIKLSpopbM8
IYsIgSiqRvv4eVhB6QGQkdHdPOrdAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAPnEv
WWNtNYJJmTQAzVUmYmuVQB1Fff9k8Cw1lrkQotmc8G/LVICeaec84Bcr1hYc7LJ4
SBp7ymERslpEeZCrFiAG/hMB+icCpPdbbAkjVW3/Yo2/SgKhak7iZvszme1NraZm
BlzuYy3PFsuUU45cRIPBsoygZ498JwrVn9/WeAM=
-----END CERTIFICATE-----`

const certStringHostnameMismatch = `-----BEGIN CERTIFICATE-----
MIIBkDCB+gIJAP/G75+MvzSQMA0GCSqGSIb3DQEBBQUAMA0xCzAJBgNVBAYTAlVT
MB4XDTE4MDcyNjE2NDM0MloXDTE4MDgyNTE2NDM0MlowDTELMAkGA1UEBhMCVVMw
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALsGFO2tmSAPtDR8YccGXhNGsQU7
YqY33cxVl1OhvZLefBawVSho/0nHhaxDQX4zA/acpNLnYu9MKo/IP1UWn1dLnYy2
rpzKUr5ROQoBCdJW7XiDl1LSABsz3XjPE7U0Wn/0LiIKLSpopbM8IYsIgSiqRvv4
eVhB6QGQkdHdPOrdAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAIbh+2deYaUdQ2w9Z
h/HDykuWhf452E/QGx2ltiEB4hj/ggxn5Hho0W5+nAjc3HRa16B0UvmyBSxSFG47
8E0+wATR37GHenDLtTgIAEv3Ax7ojTsSYI7ssm+USkhd8GfeCzNWYGO4KAUuWS1r
CFPY0q3dB4ltPdEVfgGNZYTRqIU=
-----END CERTIFICATE-----`

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
