package validator

import (
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

var checkPerformer = checker.CheckDomain

type Validatable interface {
	DomainsToValidate() ([]string, error)
	HostnamesForDomain(string) ([]string, error)
}

func ValidateRegularly(v Validatable, interval time.Duration) {
	for {
		<-time.After(interval)
		domains, err := v.DomainsToValidate()
		failed := make(map[string]checker.DomainResult)
		if err != nil {
			// log error and skip this check.
		}
		for _, domain := range domains {
			hostnames, err := v.HostnamesForDomain(domain)
			if err != nil {
				// log error and skip this check.
			}
			result := checkPerformer(domain, hostnames)
			if result.Status != 0 {
				failed[domain] = result
			}
		}
		// Async log these to sentry.
	}
}
