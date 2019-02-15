package models

import (
	"fmt"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

// Domain stores the preload state of a single domain.
type Domain struct {
	Name        string      `json:"domain"` // Domain that is preloaded
	Email       string      `json:"-"`      // Contact e-mail for Domain
	MXs         []string    `json:"mxs"`    // MXs that are valid for this domain
	MTASTSMode  string      `json:"mta_sts"`
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
// A successful scan should already have been submitted for this domain,
// and it should not already be on the policy list.
// Returns (queuability, error message, and most recent scan)
func (d *Domain) IsQueueable(db scanStore, list policyList) (bool, string, Scan) {
	scan, err := db.GetLatestScan(d.Name)
	if err != nil {
		return false, "We haven't scanned this domain yet. " +
			"Please use the STARTTLS checker to scan your domain's " +
			"STARTTLS configuration so we can validate your submission", scan
	}
	if scan.Data.Status != 0 {
		return false, "Domain hasn't passed our STARTTLS security checks", scan
	}
	if list.HasDomain(d.Name) {
		return false, "Domain is already on the policy list!", scan
	}
	// Domains without submitted MTA-STS support must match provided mx patterns.
	if d.MTASTSMode == "" {
		for _, hostname := range scan.Data.PreferredHostnames {
			if !checker.PolicyMatches(hostname, d.MXs) {
				return false, fmt.Sprintf("Hostnames %v do not match policy %v", scan.Data.PreferredHostnames, d.MXs), scan
			}
		}
	} else if !scan.SupportsMTASTS() {
		return false, "Domain does not correctly implement MTA-STS.", scan
	}
	return true, "", scan
}

// PopulateFromScan updates a Domain's fields based on a scan of that domain.
func (d *Domain) PopulateFromScan(scan Scan) {
	// We should only trust MTA-STS info from a successful MTA-STS check.
	if scan.Data.MTASTSResult != nil && scan.SupportsMTASTS() {
		d.MTASTSMode = scan.Data.MTASTSResult.Mode
		// If the domain's MXs are missing, we can take them from the scan's
		// PreferredHostnames, which must be a subset of those listed in the
		// MTA-STS policy file.
		if len(d.MXs) == 0 {
			d.MXs = scan.Data.MTASTSResult.MXs
		}
	}
}
