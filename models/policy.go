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
	GetPolicy(string) (PolicySubmission, bool, error)
	GetPolicies(bool) ([]PolicySubmission, error)
	RemovePolicy(string) (PolicySubmission, error)
}

// policyList wraps access to a read-only JSON file containing policies.
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
// Policy Submission. Domains that have already been added to the policy store
// can only:
// 1. Have their their contact e-mail address updated
// 2. Have their policy updated if they're manual and in testing.
func (p *PolicySubmission) CanUpdate(policies policyStore) bool {
	oldPolicy, ok, err := policies.GetPolicy(p.Name)
	// If something messed up, we can't add it.
	if err != nil {
		return false
	}
	// If this policy doesn't exist in the policyStore, we can add it.
	if !ok {
		return true
	}
	// If the policies are the same, return true if emails are different.
	if p.samePolicy(oldPolicy) {
		return oldPolicy.Email != p.Email
	}
	// If old policy is manual and in testing, we can update it safely (but no upgrading to enforce)
	if !oldPolicy.MTASTS && oldPolicy.Policy.Mode == "testing" && p.Policy.Mode == "testing" {
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
	if scan.Timestamp.Add(time.Hour).Before(time.Now()) {
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
func (p *PolicySubmission) PolicyListCheck(pending policyStore, store policyStore, list policyList) *checker.Result {
	result := checker.Result{Name: checker.PolicyList}
	if list.HasDomain(p.Name) {
		return result.Success()
	}
	_, ok, err := store.GetPolicy(p.Name)
	if ok {
		return result.Warning("Domain %s should soon be added to the policy list.", p.Name)
	}
	if err != nil {
		return result.Error("Error retrieving domain from database.")
	}
	_, ok, err = pending.GetPolicy(p.Name)
	if ok {
		return result.Failure("The policy submission for %s is waiting on email validation.", p.Name)
	}
	if err != nil {
		return result.Error("Error retrieving domain from database.")
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

func (p PolicySubmission) moveSubmission(from policyStore, to policyStore) error {
	err := to.PutOrUpdatePolicy(&p)
	if err != nil {
		return err
	}
	_, err = from.RemovePolicy(p.Name)
	return err
}
