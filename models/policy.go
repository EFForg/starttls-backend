package models

import (
	"fmt"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/policy"
)

// PolicySubmission represents an email domain's TLS policy submission.
type PolicySubmission struct {
	Name   string `json:"domain"` // Domain that is preloaded
	Email  string `json:"-"`      // Contact e-mail for Domain
	MTASTS bool   `json:"mta_sts"`
	Policy *policy.TLSPolicy
}

// policyStore is a simple interface for fetching and adding domain objects.
type policyStore interface {
	PutOrUpdatePolicy(*PolicySubmission) error
	GetPolicy(string) (PolicySubmission, error)
	GetPolicies(bool) ([]PolicySubmission, error)
	RemovePolicy(string) (PolicySubmission, error)
}

type policyList interface {
	HasDomain(string) bool
}

func (p *PolicySubmission) samePolicy(other PolicySubmission) bool {
	shallowEqual := p.Name == other.Name && p.MTASTS == other.MTASTS
	if p.Policy == nil {
		return shallowEqual && other.Policy == nil
	}
	return shallowEqual && p.Policy.Equals(other.Policy)
}

// CanUpdate returns whether we can update the policyStore with this particular
// Policy Submission. In some cases, you should be able to update the
// existing policy. In other cases, you shouldn't.
func (p *PolicySubmission) CanUpdate(policies policyStore) bool {
	oldPolicy, err := policies.GetPolicy(p.Name)
	// If this policy doesn't exist in the policyStore, we can add it.
	// TODO: not to conflate between real errors and "not present" errors.
	if err != nil {
		return true
	}
	// If the policies are the same, return true if emails are different.
	if p.samePolicy(oldPolicy) {
		return oldPolicy.Email != p.Email
	}
	// If old policy is manual and in testing, we can update it safely.
	if !oldPolicy.MTASTS && oldPolicy.Policy.Mode == "testing" {
		return true
	}
	return false
}

// HasValidScan checks whether this policy already has a recent scan as an initial
// sanity check. This function isn't meant to be bullet-proof since state can change
// between initial submission and final addition to the list, but we can short-circuit
// premature failures here on initial submission.
func (p *PolicySubmission) HasValidScan(scans scanStore) (bool, string) {
	scan, err := scans.GetLatestScan(p.Name)
	if err != nil {
		return false, "We haven't scanned this domain yet. " +
			"Please use the STARTTLS checker to scan your domain's " +
			"STARTTLS configuration so we can validate your submission"
	}
	if scan.Timestamp.Add(time.Minute * 10).Before(time.Now()) {
		return false, "We haven't scanned this domain recently. " +
			"Please use the STARTTLS checker to scan your domain's " +
			"STARTTLS configuration so we can validate your submission"
	}
	if scan.Data.Status != 0 {
		return false, "Domain hasn't passed our STARTTLS security checks"
	}
	// Domains without submitted MTA-STS support must match provided mx patterns.
	if !p.MTASTS {
		for _, hostname := range scan.Data.PreferredHostnames {
			if !checker.PolicyMatches(hostname, p.Policy.MXs) {
				return false, fmt.Sprintf("Hostnames %v do not match policy %v", scan.Data.PreferredHostnames, p.Policy.MXs)
			}
		}
	} else if !scan.SupportsMTASTS() {
		return false, "Domain does not correctly implement MTA-STS."
	}
	return true, ""
}

// InitializeWithToken adds this domain to the given DomainStore and initializes a validation token
// for the addition. The newly generated Token is returned.
func (p *PolicySubmission) InitializeWithToken(pending policyStore, tokens tokenStore) (string, error) {
	if err := pending.PutOrUpdatePolicy(p); err != nil {
		return "", err
	}
	token, err := tokens.PutToken(p.Name)
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

// PolicyListCheck checks the policy list status of this particular domain.
// TODO: differentiate between errors and not-in-DB
func (p *PolicySubmission) PolicyListCheck(pending policyStore, store policyStore, list policyList) *checker.Result {
	result := checker.Result{Name: checker.PolicyList}
	if list.HasDomain(p.Name) {
		return result.Success()
	}
	_, err := store.GetPolicy(p.Name)
	if err == nil {
		return result.Warning("Domain %s should soon be added to the policy list.", p.Name)
	}
	_, err = pending.GetPolicy(p.Name)
	if err == nil {
		return result.Failure("The policy submission for %s is waiting on email validation.", p.Name)
	}
	return result.Failure("Domain %s is not on the policy list.", p.Name)
}

// AsyncPolicyListCheck performs PolicyListCheck asynchronously.
// domainStore and policyList should be safe for concurrent use.
func (p PolicySubmission) AsyncPolicyListCheck(pending policyStore, store policyStore, list policyList) <-chan checker.Result {
	result := make(chan checker.Result)
	go func() { result <- *p.PolicyListCheck(pending, store, list) }()
	return result
}
