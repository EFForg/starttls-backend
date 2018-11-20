package validator

import (
	"fmt"
	"log"
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
	raven.CaptureMessageAndWait("Validation failed for previously validated domain",
		map[string]string{
			"validatorName": name,
			"domain":        result.Domain,
			"status":        fmt.Sprintf("%d", result.Status),
		},
		result)
}

type checkPerformer func(string, []string, time.Duration) checker.DomainResult
type reportFailure func(string, string, checker.DomainResult)

// Helper function that's agnostic to how checks are performed how to
// report failures. The two callbacks should only be used as test hooks.
func validateRegularly(v DomainPolicyStore, interval time.Duration,
	check checkPerformer, report reportFailure) {
	for {
		<-time.After(interval)
		log.Printf("[%s validator] starting regular validation", v.GetName())
		domains, err := v.DomainsToValidate()
		if err != nil {
			log.Printf("[%s validator] Could not retrieve domains: %v", v.GetName(), err)
			continue
		}
		for _, domain := range domains {
			hostnames, err := v.HostnamesForDomain(domain)
			if err != nil {
				log.Printf("[%s validator] Could not retrieve policy for domain %s: %v", v.GetName(), domain, err)
				continue
			}
			result := check(domain, hostnames, 10*time.Second)
			if result.Status != 0 && report != nil {
				log.Printf("[%s validator] %s failed; sending report", v.GetName(), domain)
				report(v.GetName(), domain, result)
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
