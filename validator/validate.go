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

type performCheckFunc func(string, []string) checker.DomainResult
type reportFailureFunc func(string, string, checker.DomainResult)

// Validator is a config object to specify how a validator behaves--
// How often validation occurs, which domains to check, what checks
// are performed, and how failures are reported.
type Validator struct {
	Name            string
	Interval        time.Duration
	Store           DomainPolicyStore
	FailureReporter reportFailureFunc
	checkPerformer  performCheckFunc
}

// performCheck can be overridden for testing purposes. Otherwise, it shouldn't change.
func (v *Validator) performCheck(domain string, hostnames []string) checker.DomainResult {
	if v.checkPerformer == nil {
		c := checker.Checker{}
		return c.CheckDomain(domain, hostnames)
	}
	return v.checkPerformer(domain, hostnames)
}

// By default, failures are always reported to Sentry.
func (v *Validator) reportFailure(domain string, result checker.DomainResult) {
	reportToSentry(v.Name, domain, result)
	if v.FailureReporter != nil {
		v.FailureReporter(v.Name, domain, result)
	}
}

// Default interval is 24 hours.
func (v *Validator) getInterval() time.Duration {
	if v.Interval == 0 {
		return 24 * time.Hour
	}
	return v.Interval
}

// Start begins the infinite loop for this validator.
// The first validation occurs `v.Interval` time after Start() is called.
func (v Validator) Start() {
	for {
		<-time.After(v.getInterval())
		log.Printf("[%s validator] starting regular validation", v.Name)
		domains, err := v.Store.DomainsToValidate()
		if err != nil {
			log.Printf("[%s validator] Could not retrieve domains: %v", v.Name, err)
			continue
		}
		for _, domain := range domains {
			hostnames, err := v.Store.HostnamesForDomain(domain)
			if err != nil {
				log.Printf("[%s validator] Could not retrieve policy for domain %s: %v", v.Name, domain, err)
				continue
			}
			result := v.performCheck(domain, hostnames)
			if result.Status != 0 {
				log.Printf("[%s validator] %s failed; sending report", v.Name, domain)
				v.reportFailure(domain, result)
			}
		}
	}
}
