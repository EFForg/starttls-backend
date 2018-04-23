package main

import (
    "fmt"
    "time"
    "math/rand"
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
    UseToken(string) (TokenData, error)
}

// Straw-man in-memory database (for testing!)
type MemDatabase struct {
    domains map[string]DomainData
    scans map[string][]ScanData
    tokens map[string]TokenData
}

func randToken() string {
    b := make([]byte, 8)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}

func (db *MemDatabase) UseToken(token_str string) (TokenData, error) {
    token, ok := db.tokens[token_str]
    if ! ok {
        return TokenData{}, fmt.Errorf("This token doesn't exist!")
    }
    if token.Used {
        return TokenData{}, fmt.Errorf("This token has already been used!")
    }
    if token.Expires.Before(time.Now()) {
        return TokenData{}, fmt.Errorf("This token has expired!")
    }
    db.tokens[token_str] = TokenData {
        Domain: token.Domain,
        Token: token.Token,
        Expires: token.Expires,
        Used: true,
    }
    return db.tokens[token_str], nil
}

func (db *MemDatabase) PutToken(domain string) (TokenData, error) {
    token := TokenData {
        Domain: domain,
        Token: randToken(),
        // TODO: expiry time as constant
        Expires: time.Now().Add(time.Duration(time.Hour * 72 )),
        Used: false,
    }
    db.tokens[token.Token] = token
    return token, nil
}

func (db *MemDatabase) PutScan(scanData ScanData) error {
    if _, ok := db.scans[scanData.Domain]; !ok {
        db.scans[scanData.Domain] = make([]ScanData, 0)
    }
    db.scans[scanData.Domain] = append(db.scans[scanData.Domain],scanData)
    return nil
}

func (db MemDatabase) GetLatestScan(domain string) (ScanData, error) {
    val, ok := db.scans[domain]
    if !ok {
        return ScanData{}, fmt.Errorf("No scans conducted for domain %s", domain)
    }
    return val[len(val)-1], nil
}

func (db MemDatabase) GetAllScans(domain string) ([]ScanData, error) {
    val, ok := db.scans[domain]
    if !ok {
        return nil, fmt.Errorf("No scans conducted for domain %s", domain)
    }
    return val, nil
}

func (db *MemDatabase) PutDomain(domainData DomainData) error {
    db.domains[domainData.Name] = domainData
    return nil
}

func (db MemDatabase) GetDomain(domain string) (DomainData, error) {
    return db.domains[domain], nil
}

func (db MemDatabase) GetDomains(state DomainState) ([]DomainData, error) {
    data := make([]DomainData, 0)
    for _, value := range db.domains {
        if value.State == state {
            data = append(data, value)
        }
    }
    return data, nil
}

