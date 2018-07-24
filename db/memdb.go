package db

import (
	"fmt"
	"math/rand"
	"time"
)

// MemDatabase is a straw-man in-memory database for testing.
// This DB does not persist.
type MemDatabase struct {
	cfg     Config
	domains map[string]DomainData
	scans   map[string][]ScanData
	tokens  map[string]TokenData
}

// InitMemDatabase initializes a MemDatabase.
func InitMemDatabase(cfg Config) *MemDatabase {
	return &MemDatabase{
		cfg:     cfg,
		domains: make(map[string]DomainData),
		scans:   make(map[string][]ScanData),
		tokens:  make(map[string]TokenData),
	}
}

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// GetTokenByDomain gets the token for a domain name.
func (db *MemDatabase) GetTokenByDomain(domain string) (string, error) {
	for token, tokenData := range db.tokens {
		if tokenData.Domain == domain {
			return token, nil
		}
	}
	return "", fmt.Errorf("no token found for domain %s", domain)
}

// UseToken uses the e-mail token specified by tokenStr.
func (db *MemDatabase) UseToken(tokenStr string) (string, error) {
	token, ok := db.tokens[tokenStr]
	if !ok {
		return "", fmt.Errorf("token doesn't exist")
	}
	if token.Used {
		return "", fmt.Errorf("token has already been used")
	}
	if token.Expires.Before(time.Now()) {
		return "", fmt.Errorf("token has expired")
	}
	db.tokens[tokenStr] = TokenData{
		Domain:  token.Domain,
		Token:   token.Token,
		Expires: token.Expires,
		Used:    true,
	}
	return token.Domain, nil
}

// PutToken inserts a randomly generated token for domain. Returns the token.
func (db *MemDatabase) PutToken(domain string) (TokenData, error) {
	existingToken, err := db.GetTokenByDomain(domain)
	if err == nil {
		delete(db.tokens, existingToken)
	}
	token := TokenData{
		Domain: domain,
		Token:  randToken(),
		// TODO: expiry time as constant
		Expires: time.Now().Add(time.Duration(time.Hour * 72)),
		Used:    false,
	}
	db.tokens[token.Token] = token
	return token, nil
}

// PutScan puts a scandata object.
func (db *MemDatabase) PutScan(scanData ScanData) error {
	if _, ok := db.scans[scanData.Domain]; !ok {
		db.scans[scanData.Domain] = make([]ScanData, 0)
	}
	db.scans[scanData.Domain] = append(db.scans[scanData.Domain], scanData)
	return nil
}

// GetLatestScan retrives the latest scan.
func (db MemDatabase) GetLatestScan(domain string) (ScanData, error) {
	val, ok := db.scans[domain]
	if !ok {
		return ScanData{}, fmt.Errorf("no scans found for domain %s", domain)
	}
	return val[len(val)-1], nil
}

// GetAllScans retrieves all the scans for a particular domain.
func (db MemDatabase) GetAllScans(domain string) ([]ScanData, error) {
	val, ok := db.scans[domain]
	if !ok {
		return nil, fmt.Errorf("no scans found for domain %s", domain)
	}
	return val, nil
}

// PutDomain inserts a new domain into the queue.
func (db *MemDatabase) PutDomain(domainData DomainData) error {
	db.domains[domainData.Name] = domainData
	return nil
}

// GetDomain retrieves the queue status for a particular domain.
func (db MemDatabase) GetDomain(domain string) (DomainData, error) {
	return db.domains[domain], nil
}

// GetDomains retrieves all domains in a parituclar queue status.
func (db MemDatabase) GetDomains(state DomainState) ([]DomainData, error) {
	data := make([]DomainData, 0)
	for _, value := range db.domains {
		if value.State == state {
			data = append(data, value)
		}
	}
	return data, nil
}

// ClearTables clears all the tables.
func (db *MemDatabase) ClearTables() error {
	db.domains = make(map[string]DomainData)
	db.scans = make(map[string][]ScanData)
	db.tokens = make(map[string]TokenData)
	return nil
}
