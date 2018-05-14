package db

import (
	"fmt"
	"math/rand"
	"time"
)

// Straw-man in-memory database (for testing!)
type MemDatabase struct {
	cfg     Config
	domains map[string]DomainData
	scans   map[string][]ScanData
	tokens  map[string]TokenData
}

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

func (db *MemDatabase) UseToken(token_str string) (string, error) {
	token, ok := db.tokens[token_str]
	if !ok {
		return "", fmt.Errorf("This token doesn't exist!")
	}
	if token.Used {
		return "", fmt.Errorf("This token has already been used!")
	}
	if token.Expires.Before(time.Now()) {
		return "", fmt.Errorf("This token has expired!")
	}
	db.tokens[token_str] = TokenData{
		Domain:  token.Domain,
		Token:   token.Token,
		Expires: token.Expires,
		Used:    true,
	}
	return token.Domain, nil
}

func (db *MemDatabase) getTokenForDomain(domain string) (string, error) {
	for token, tokenData := range db.tokens {
		if tokenData.Domain == domain {
			return token, nil
		}
	}
	return "", fmt.Errorf("Couldn't find an entry for this domain!")
}

func (db *MemDatabase) PutToken(domain string) (TokenData, error) {
	existingToken, err := db.getTokenForDomain(domain)
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

func (db *MemDatabase) PutScan(scanData ScanData) error {
	if _, ok := db.scans[scanData.Domain]; !ok {
		db.scans[scanData.Domain] = make([]ScanData, 0)
	}
	db.scans[scanData.Domain] = append(db.scans[scanData.Domain], scanData)
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

func (db *MemDatabase) ClearTables() error {
	db.domains = make(map[string]DomainData)
	db.scans = make(map[string][]ScanData)
	db.tokens = make(map[string]TokenData)
	return nil
}
