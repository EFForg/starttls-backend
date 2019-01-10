package models

import "time"

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
