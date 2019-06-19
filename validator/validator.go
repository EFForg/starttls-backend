package validator

import (
	"context"
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

// Called with failure by defaault.
func reportToSentry(name string, domain string, result checker.DomainResult) {
	raven.CaptureMessageAndWait("Validation failed for previously validated domain",
		map[string]string{
			"validatorName": name,
			"domain":        result.Domain,
			"status":        fmt.Sprintf("%d", result.Status),
		},
		result)
}

type checkPerformer func(context.Context, string, []string) checker.DomainResult
type resultCallback func(string, string, checker.DomainResult)

// Validator runs checks regularly against domain policies. This structure
// defines the configurations.
type Validator struct {
	// Name: Required with which to refer to this validator. Appears in log files and
	// error reports.
	Name string
	// Store: Required-- store from which the validator fetches policies to validate.
	Store DomainPolicyStore
	// Interval: optional; time at which validator should re-run.
	// If not set, default interval is 1 day.
	Interval time.Duration
	// OnFailure: optional. Called when a particular policy validation fails. Defaults to
	// a sentry report.
	OnFailure resultCallback
	// OnSuccess: optional. Called when a particular policy validation succeeds.
	OnSuccess resultCallback
	// checkPerformer: performs the check.
	checkPerformer checkPerformer
}

func (v *Validator) checkPolicy(ctx context.Context, domain string, hostnames []string) checker.DomainResult {
	if v.checkPerformer == nil {
		c := checker.Checker{
			Cache: checker.MakeSimpleCache(time.Hour),
		}
		v.checkPerformer = c.CheckDomain
	}
	return v.checkPerformer(ctx, domain, hostnames)
}

func (v *Validator) interval() time.Duration {
	if v.Interval != 0 {
		return v.Interval
	}
	return time.Hour * 24
}

func (v *Validator) policyFailed(name string, domain string, result checker.DomainResult) {
	if v.OnFailure != nil {
		v.OnFailure(name, domain, result)
	}
	reportToSentry(name, domain, result)
}

func (v *Validator) policyPassed(name string, domain string, result checker.DomainResult) {
	if v.OnSuccess != nil {
		v.OnSuccess(name, domain, result)
	}
}

// Run performs a single validation.
// Validation failures induce `policyFailed`, and successes cause `policyPassed`.
func (v *Validator) runOnce(ctx context.Context) {
	log.Printf("[%s validator] starting regular validation", v.Name)
	domains, err := v.Store.DomainsToValidate()
	if err != nil {
		log.Printf("[%s validator] Could not retrieve domains: %v", v.Name, err)
		return
	}
	for _, domain := range domains {
		hostnames, err := v.Store.HostnamesForDomain(domain)
		if err != nil {
			log.Printf("[%s validator] Could not retrieve policy for domain %s: %v", v.Name, domain, err)
			return
		}
		result := v.checkPolicy(ctx, domain, hostnames)
		if result.Status != 0 {
			log.Printf("[%s validator] %s failed; sending report", v.Name, domain)
			v.policyFailed(v.Name, domain, result)
		} else {
			v.policyPassed(v.Name, domain, result)
		}
	}
}

func (v *Validator) runLoop(ctx context.Context, exited chan struct{}) {
	ticker := time.NewTicker(v.Interval)
	for {
		select {
		case <-ticker.C:
			v.runOnce(ctx)
		case <-ctx.Done():
			log.Printf("Shutting down %s validator...", v.Name)
			exited <- struct{}{}
			return
		}
	}
}

// ValidateRegularly regularly runs checker.CheckDomain against a Domain-
// Hostname map. Interval specifies the interval to wait between each run.
// Failures are reported to Sentry.
func ValidateRegularly(ctx context.Context, exited chan struct{}, name string, store DomainPolicyStore, interval time.Duration) {
	v := Validator{
		Name:     name,
		Store:    store,
		Interval: interval,
	}
	v.runLoop(ctx, exited)
}
