package models

import (
	"time"
)

// Domain stores the preload state of a single domain.
type Domain struct {
	Name        string      `json:"domain"` // Domain that is preloaded
	Email       string      `json:"-"`      // Contact e-mail for Domain
	MXs         []string    `json:"mxs"`    // MXs that are valid for this domain
	State       DomainState `json:"state"`
	LastUpdated time.Time   `json:"last_updated"`
}

// DomainState represents the state of a single domain.
type DomainState string

// Possible values for DomainState
const (
	StateUnknown     = "unknown"     // Domain was never submitted, so we don't know.
	StateUnvalidated = "unvalidated" // E-mail token for this domain is unverified
	StateQueued      = "queued"      // Queued for addition at next addition date.
	StateFailed      = "failed"      // Requested to be queued, but failed verification.
	StateAdded       = "added"       // On the list.
)

type policyList interface {
	HasDomain(string) bool
}

type scanStore interface {
	GetLatestScan(string) (Scan, error)
}

// IsQueueable returns true if a domain can be submitted for validation and
// queueing to the STARTTLS Everywhere Policy List.
func (d *Domain) IsQueueable(db scanStore, list policyList) (bool, string) {
	// Check if successful scan occurred.
	scan, err := db.GetLatestScan(d.Name)
	if err != nil {
		return false, "We haven't scanned this domain yet. " +
			"Please use the STARTTLS checker to scan your domain's " +
			"STARTTLS configuration so we can validate your submission"
	}
	if scan.Data.Status != 0 {
		return false, "Domain hasn't passed our STARTTLS security checks"
	}
	// Check to see it's not already on the Policy List.
	if list.HasDomain(d.Name) {
		return false, "Domain is already on the policy list!"
	}
	return true, ""
}
