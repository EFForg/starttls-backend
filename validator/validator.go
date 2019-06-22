package validator

import (
	"fmt"
	"log"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/policy"
	"github.com/getsentry/raven-go"
)

// DomainPolicyStore is an interface for any back-end that
// stores a map of domains to its "policy" (in this case, just the
// expected hostnames).
type DomainPolicyStore interface {
	DomainsToValidate() ([]string, error)
	GetPolicy(string) (models.PolicySubmission, bool, error)
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

type checkPerformer func(models.PolicySubmission) checker.DomainResult
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
	// CheckPerformer: performs the check.
	CheckPerformer checkPerformer
}

func resultMTASTSToPolicy(r *checker.MTASTSResult) *policy.TLSPolicy {
	return &policy.TLSPolicy{Mode: r.Mode, MXs: r.MXs}
}

func getMTASTSUpdater(update func(*models.PolicySubmission) error) checkPerformer {
	c := checker.Checker{Cache: checker.MakeSimpleCache(time.Hour)}
	return func(p models.PolicySubmission) checker.DomainResult {
		if p.MTASTS {
			result := c.CheckDomain(p.Name, []string{})
			if !p.Policy.Equals(resultMTASTSToPolicy(result.MTASTSResult)) {
				if err := update(&p); err != nil {
					reportToSentry(fmt.Sprintf("couldn't update policy in DB: %v", err), p.Name, result)
				}
			}
		}
		return c.CheckDomain(p.Name, p.Policy.MXs)
	}
}

func (v *Validator) checkPolicy(p *models.PolicySubmission) checker.DomainResult {
	if v.CheckPerformer == nil {
		c := checker.Checker{Cache: checker.MakeSimpleCache(time.Hour)}
		v.CheckPerformer = func(policy models.PolicySubmission) checker.DomainResult {
			return c.CheckDomain(p.Name, p.Policy.MXs)
		}
	}
	return v.CheckPerformer(*p)
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

// Run starts the endless loop of validations. The first validation happens after the given
// Interval. Validation failures induce `policyFailed`, and successes cause `policyPassed`.
func (v *Validator) Run() {
	for {
		<-time.After(v.interval())
		log.Printf("[%s validator] starting regular validation", v.Name)
		domains, err := v.Store.DomainsToValidate()
		if err != nil {
			log.Printf("[%s validator] Could not retrieve domains: %v", v.Name, err)
			continue
		}
		for _, domain := range domains {
			policy, ok, err := v.Store.GetPolicy(domain)
			if err != nil || !ok {
				log.Printf("[%s validator] Could not retrieve policy for domain %s: %v", v.Name, domain, err)
				continue
			}
			result := v.checkPolicy(&policy)
			if result.Status != 0 {
				log.Printf("[%s validator] %s failed; sending report", v.Name, domain)
				v.policyFailed(v.Name, domain, result)
			} else {
				v.policyPassed(v.Name, domain, result)
			}
		}
	}
}
