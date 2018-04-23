package main

import (
    "time"
)

///////////////////////////////////////
//  *****   DATABASE SCHEMA   *****  //
///////////////////////////////////////

// Each of these mirrors a table row.

// ScanData each represent the result of a single scan, conducted using
// starttls-checker.
type ScanData struct {
    Domain     string           // Input domain
    Data       string           // JSON blob: scan results from starttls-checker
    Timestamp  time.Time        // Time at which this scan was conducted
}

// DomainStatus: represents the state of a single domain.
type DomainState string;

const (
    StateUnknown       = "unknown"      // Domain was never submitted, so we don't know.
    StateUnvalidated   = "unvalidated"  // E-mail token for this domain is unverified
    StateQueued        = "queued"       // Queued for addition at next addition date.
    StateFailed        = "failed"       // Requested to be queued, but failed verification.
    StateAdded         = "added"        // On the list.
)

// DomainData stores the preload state of a single domain.
type DomainData struct {
    Name       string           // Domain that is preloaded
    Email      string           // Contact e-mail for Domain
    MXs        []string         // MXs that are valid for this domain
    State      DomainState
}

// TokenData stores the state of an e-mail verification token.
type TokenData struct {
    Domain       string         // Domain for which we're verifying the e-mail.
    Token        string         // Token that we're expecting.
    Expires      time.Time      // When this token expires.
    Used         bool           // Whether this token was used.
}


// These are the things that the Database should be able to do.
// Slightly more limited than CRUD for all the schemas.
type Database interface {
    // Puts new scandata for domain 
    PutScan(ScanData) error
    // Retrieves most recent scandata for domain
    GetLatestScan(string) (ScanData, error)
    // Retrieves all scandata for domain
    GetAllScans(string) ([]ScanData, error)
    // Upserts domain state.
    PutDomain(DomainData) error
    // Retrieves state of a domain
    GetDomain(string) (DomainData, error)
    // Retrieves all domains in a particular state.
    GetDomains(DomainState) ([]DomainData, error)
    // Creates a token in the db
    PutToken(string) (TokenData, error)
    // Uses a token in the db
    UseToken(string) (string, error)
}

