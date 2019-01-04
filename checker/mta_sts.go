package checker

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

func filterByPrefix(records []string, prefix string) []string {
	filtered := []string{}
	for _, elem := range records {
		if elem[0:len(prefix)] == prefix {
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

func checkMTASTSRecord(domain string) CheckResult {
	result := CheckResult{Name: "mta-sts-txt"}
	records, err := net.LookupTXT(fmt.Sprintf("_mta-sts.%s", domain))
	if err != nil {
		return result.Failure("Couldn't find MTA-STS TXT record: %v", err)
	}
	return validateMTASTSRecord(records, result)
}

func validateMTASTSRecord(records []string, result CheckResult) CheckResult {
	records = filterByPrefix(records, "v=STSv1")
	if len(records) != 1 {
		return result.Failure("exactly 1 MTA-STS TXT record required, found %d", len(records))
	}
	record := getKeyValuePairs(records[0], ";", "=")

	idPattern := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !idPattern.MatchString(record["id"]) {
		return result.Failure("invalid id %s", record["id"])
	}
	return result.Success()
}

func checkMTASTSPolicyFile(domain string, hostnameResults map[string]HostnameResult) CheckResult {
	result := CheckResult{Name: "policy_file"}
	client := &http.Client{
		// Don't follow redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	resp, err := client.Get(policyURL)
	if err != nil {
		return result.Failure("Couldn't find policy file: %v", err)
	}
	if resp.StatusCode != 200 {
		return result.Failure("Couldn't get policy file: %s", resp.Status)
	}
	// Media type should be text/plain, ignoring other Content-Type parms.
	// Format: Content-Type := type "/" subtype *[";" parameter]
	for _, contentType := range resp.Header["Content-Type"] {
		contentType := strings.ToLower(contentType)
		if strings.HasPrefix(contentType, "text/plain") {
			return result.Warning("Media type must be text/plain")
		}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result.Error("Couldn't read policy file: %v", err)
	}

	result, policy := validateMTASTSPolicyFile(string(body), result)
	return validateMTASTSMXs(strings.Split(policy["mx"], " "), hostnameResults, result)
}

func validateMTASTSPolicyFile(body string, result CheckResult) (CheckResult, map[string]string) {
	policy := getKeyValuePairs(body, "\n", ":")

	if policy["version"] != "STSv1" {
		result.Failure("Policy version must be STSv1")
	}

	if policy["mode"] == "" {
		result.Failure("Policy file must specify mode")
	}
	if m := policy["mode"]; m != "enforce" && m != "testing" && m != "none" {
		result.Failure("Mode must be one of 'enforce', 'testing', or 'none', got %s", m)
	}

	if policy["max_age"] == "" {
		result.Failure("Policy file must specify max_age")
	}
	if i, err := strconv.Atoi(policy["max_age"]); err != nil || i <= 0 || i > 31557600 {
		result.Failure("max_age must be a positive integer <= 31557600")
	}

	return result.Success(), policy
}

func validateMTASTSMXs(policyFileMXs []string, dnsMXs map[string]HostnameResult,
	result CheckResult) CheckResult {
	for dnsMX, dnsMXResult := range dnsMXs {
		if !dnsMXResult.couldConnect() {
			// Ignore hostnames we couldn't connect to, they may be spam traps.
			continue
		}
		if !policyMatches(dnsMX, policyFileMXs) {
			result.Warning("%s appears in the DNS record but not the MTA-STS policy file",
				dnsMX)
		} else if !dnsMXResult.couldSTARTTLS() {
			result.Warning("%s appears in the DNS record and MTA-STS policy file, but doesn't support STARTTLS",
				dnsMX)
		}
	}
	return result
}

func checkMTASTS(domain string, hostnameResults map[string]HostnameResult) ResultGroup {
	result := ResultGroup{
		Status: Success,
		Checks: make(map[string]CheckResult),
	}
	result.addCheck(checkMTASTSRecord(domain))
	result.addCheck(checkMTASTSPolicyFile(domain, hostnameResults))
	return result
}
