package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MTASTSResult represents the result of a check for inbound MTA-STS support.
type MTASTSResult struct {
	*Result
	Policy string // Text of MTA-STS policy file
	Mode   string
	MXs    []string
}

// MakeMTASTSResult constructs a base result object and returns its pointer.
func MakeMTASTSResult() *MTASTSResult {
	return &MTASTSResult{
		Result: MakeResult(MTASTS),
	}
}

// MarshalJSON prevents MTASTSResult from inheriting the version of MarshalJSON
// implemented by Result.
func (m MTASTSResult) MarshalJSON() ([]byte, error) {
	// type FakeMTASTSResult MTASTSResult
	type FakeResult Result
	return json.Marshal(struct {
		FakeResult
		Policy string   `json:"policy"`
		Mode   string   `json:"mode"`
		MXs    []string `json:"mxs"`
	}{
		FakeResult: FakeResult(*m.Result),
		Policy:     m.Policy,
		Mode:       m.Mode,
		MXs:        m.MXs,
	})
}

func filterByPrefix(records []string, prefix string) []string {
	filtered := []string{}
	for _, elem := range records {
		if strings.HasPrefix(elem, prefix) {
			filtered = append(filtered, elem)
		}
	}
	return filtered
}

func getKeyValuePairs(record string, lineDelimiter string,
	pairDelimiter string) map[string]string {
	parsed := make(map[string]string)
	for _, line := range strings.Split(record, lineDelimiter) {
		split := strings.Split(strings.TrimSpace(line), pairDelimiter)
		if len(split) != 2 {
			continue
		}
		key := strings.TrimSpace(split[0])
		value := strings.TrimSpace(split[1])
		if parsed[key] == "" {
			parsed[key] = value
		} else {
			parsed[key] = parsed[key] + " " + value
		}
	}
	return parsed
}

func checkMTASTSRecord(domain string, timeout time.Duration) *Result {
	result := MakeResult(MTASTSText)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var r net.Resolver
	records, err := r.LookupTXT(ctx, fmt.Sprintf("_mta-sts.%s", domain))
	if err != nil {
		return result.Failure("Couldn't find an MTA-STS TXT record: %v.", err)
	}
	return validateMTASTSRecord(records, result)
}

func validateMTASTSRecord(records []string, result *Result) *Result {
	records = filterByPrefix(records, "v=STSv1")
	if len(records) != 1 {
		return result.Failure("Exactly 1 MTA-STS TXT record required, found %d.", len(records))
	}
	record := getKeyValuePairs(records[0], ";", "=")

	idPattern := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !idPattern.MatchString(record["id"]) {
		return result.Failure("Invalid MTA-STS TXT record id %s.", record["id"])
	}
	return result.Success()
}

func checkMTASTSPolicyFile(domain string, hostnameResults map[string]HostnameResult, timeout time.Duration) (*Result, string, map[string]string) {
	result := MakeResult(MTASTSPolicyFile)
	client := &http.Client{
		Timeout: timeout,
		// Don't follow redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	resp, err := client.Get(policyURL)
	if err != nil {
		return result.Failure("Couldn't find policy file at %s.", policyURL), "", map[string]string{}
	}
	if resp.StatusCode != 200 {
		return result.Failure("Couldn't get policy file: %s returned %s.", policyURL, resp.Status), "", map[string]string{}
	}
	// Media type should be text/plain, ignoring other Content-Type parms.
	// Format: Content-Type := type "/" subtype *[";" parameter]
	for _, contentType := range resp.Header["Content-Type"] {
		contentType := strings.ToLower(contentType)
		if !strings.HasPrefix(contentType, "text/plain") {
			result.Warning("The media type specified by your policy file's Content-Type header should be text/plain.")
		}
	}
	defer resp.Body.Close()
	// Read up to 64,000 bytes of response body.
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 64000))
	if err != nil {
		return result.Error("Couldn't read policy file: %v.", err), "", map[string]string{}
	}

	policy := validateMTASTSPolicyFile(string(body), result)
	validateMTASTSMXs(strings.Split(policy["mx"], " "), hostnameResults, result)
	return result, string(body), policy
}

func validateMTASTSPolicyFile(body string, result *Result) map[string]string {
	policy := getKeyValuePairs(body, "\n", ":")

	if policy["version"] != "STSv1" {
		result.Failure("Your MTA-STS policy file version must be STSv1.")
	}

	if policy["mode"] == "" {
		result.Failure("Your MTA-STS policy file must specify mode.")
	}
	if m := policy["mode"]; m == "testing" {
		result.Warning("You're still in \"testing\" mode; senders won't enforce TLS when connecting to your mailservers. We recommend switching from \"testing\" to \"enforce\" to get the full security benefits of MTA-STS, as long as it hasn't been affecting your deliverability.")
	} else if m == "none" {
		result.Failure("MTA-STS policy is in \"none\" mode; senders won't enforce TLS when connecting to your mailservers.")
	} else if m != "enforce" {
		result.Failure("Mode must be one of \"enforce\", \"testing\", or \"none\", got %s", m)
	}

	if policy["max_age"] == "" {
		result.Failure("Your MTA-STS policy file must specify max_age.")
	}
	if i, err := strconv.Atoi(policy["max_age"]); err != nil || i <= 0 || i > 31557600 {
		result.Failure("MTA-STS max_age must be a positive integer <= 31557600.")
	}

	return policy
}

func validateMTASTSMXs(policyFileMXs []string, dnsMXs map[string]HostnameResult,
	result *Result) {
	for dnsMX, dnsMXResult := range dnsMXs {
		if !dnsMXResult.couldConnect() {
			// Ignore hostnames we couldn't connect to, they may be spam traps.
			continue
		}
		if !PolicyMatches(dnsMX, policyFileMXs) {
			result.Failure("%s appears in the DNS record but not the MTA-STS policy file",
				dnsMX)
		} else if !dnsMXResult.couldSTARTTLS() {
			result.Failure("%s appears in the DNS record and MTA-STS policy file, but doesn't support STARTTLS",
				dnsMX)
		}
	}
}

func (c Checker) checkMTASTS(domain string, hostnameResults map[string]HostnameResult) *MTASTSResult {
	if c.checkMTASTSOverride != nil {
		// Allow the Checker to mock this function.
		return c.checkMTASTSOverride(domain, hostnameResults)
	}
	result := MakeMTASTSResult()
	result.addCheck(checkMTASTSRecord(domain, c.timeout()))
	policyResult, policy, policyMap := checkMTASTSPolicyFile(domain, hostnameResults, c.timeout())
	result.addCheck(policyResult)
	result.Policy = policy
	result.Mode = policyMap["mode"]
	result.MXs = strings.Split(policyMap["mx"], " ")
	return result
}
