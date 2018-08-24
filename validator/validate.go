package validator

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/getsentry/raven-go"
)

// DomainPolicyStore is an interface for any back-end that
// stores a map of domains to its "policy" (in this case, just the
// expected hostnames).
type DomainPolicyStore interface {
	GetName() string
	DomainsToValidate() ([]string, error)
	HostnamesForDomain(string) ([]string, error)
}

func reportToSentry(name string, domain string, result checker.DomainResult) {
	payload, _ := json.Marshal(result)
	raven.CaptureError(fmt.Errorf(string(payload)),
		map[string]string{
			"validatorName": name,
			"status":        fmt.Sprintf("%d", result.Status),
		})
}

type checkPerformer func(string, []string) checker.DomainResult
type reportFailure func(string, string, checker.DomainResult)

// Helper function that's agnostic to how checks are performed how to
// report failures. The two callbacks should only be used as test hooks.
func validateRegularly(v DomainPolicyStore, interval time.Duration,
	check checkPerformer, report reportFailure) {
	for {
		<-time.After(interval)
		domains, err := v.DomainsToValidate()
		if err != nil {
			// log error and skip this check.
		}
		for _, domain := range domains {
			hostnames, err := v.HostnamesForDomain(domain)
			if err != nil {
				// log error and skip this check.
			}
			result := check(domain, hostnames)
			if result.Status != 0 && report != nil {
				report(v.GetName(), domain, result)
				// and log to DB?
			}
		}
	}
}

// ValidateRegularly regularly runs checker.CheckDomain against a Domain-
// Hostname map. Interval specifies the interval to wait between each run.
// Failures are reported to Sentry.
func ValidateRegularly(v DomainPolicyStore, interval time.Duration) {
	validateRegularly(v, interval, checker.CheckDomain, reportToSentry)
}
