package db

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

///////////////////////////////////////
//  *****   DATABASE SCHEMA   *****  //
///////////////////////////////////////

// Each of these mirrors a table row.

// ScanData each represent the result of a single scan, conducted using
// starttls-checker.
type ScanData struct {
	Domain    string    `json:"domain"`    // Input domain
	Data      string    `json:"scandata"`  // JSON blob: scan results from starttls-checker
	Timestamp time.Time `json:"timestamp"` // Time at which this scan was conducted
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

// DomainData stores the preload state of a single domain.
type DomainData struct {
	Name  string      `json:"domain"` // Domain that is preloaded
	Email string      `json:"-"`      // Contact e-mail for Domain
	MXs   []string    `json:"mxs"`    // MXs that are valid for this domain
	State DomainState `json:"state"`
}

// TokenData stores the state of an e-mail verification token.
type TokenData struct {
	Domain  string    `json:"domain"`  // Domain for which we're verifying the e-mail.
	Token   string    `json:"token"`   // Token that we're expecting.
	Expires time.Time `json:"expires"` // When this token expires.
	Used    bool      `json:"used"`    // Whether this token was used.
}

// Database interface: These are the things that the Database should be able to do.
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
	ClearTables() error
}

// Config is a configuration struct for a Database.
type Config struct {
	Port          string
	DbHost        string
	DbName        string
	DbUsername    string
	DbPass        string
	DbTokenTable  string
	DbScanTable   string
	DbDomainTable string
}

// Default configuration values. Can be overwritten by env vars of the same name.
var configDefaults = map[string]string{
	"PORT":            "8080",
	"DB_HOST":         "localhost",
	"DB_NAME":         "starttls",
	"DB_USERNAME":     "postgres",
	"DB_PASSWORD":     "postgres",
	"DB_TOKEN_TABLE":  "tokens",
	"DB_DOMAIN_TABLE": "domains",
	"DB_SCAN_TABLE":   "scans",
}

func getEnvOrDefault(varName string) string {
	godotenv.Load()
	envVar := os.Getenv(varName)
	if len(envVar) == 0 {
		envVar = configDefaults[varName]
	}
	return envVar
}

// LoadEnvironmentVariables loads relevant environment variables into a
// Config object.
func LoadEnvironmentVariables() (Config, error) {
	return Config{
		Port:          getEnvOrDefault("PORT"),
		DbHost:        getEnvOrDefault("DB_HOST"),
		DbName:        getEnvOrDefault("DB_NAME"),
		DbUsername:    getEnvOrDefault("DB_USERNAME"),
		DbPass:        getEnvOrDefault("DB_PASSWORD"),
		DbTokenTable:  getEnvOrDefault("DB_TOKEN_TABLE"),
		DbDomainTable: getEnvOrDefault("DB_DOMAIN_TABLE"),
		DbScanTable:   getEnvOrDefault("DB_SCAN_TABLE"),
	}, nil
}
