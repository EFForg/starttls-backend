package db

import (
	"flag"
	"os"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
)

// Database interface: These are the things that the Database should be able to do.
// Slightly more limited than CRUD for all the schemas.
type Database interface {
	// Puts new scandata for domain
	PutScan(models.Scan) error
	// Retrieves most recent scandata for domain
	GetLatestScan(string) (models.Scan, error)
	// Retrieves all scandata for domain
	GetAllScans(string) ([]models.Scan, error)
	// Gets the token for a domain
	GetTokenByDomain(string) (string, error)
	// Creates a token in the db
	PutToken(string) (models.Token, error)
	// Uses a token in the db
	UseToken(string) (string, error)
	// Adds a bounce or complaint notification to the email blacklist.
	PutBlacklistedEmail(email string, reason string, timestamp string) error
	// Returns true if we've blacklisted an email.
	IsBlacklistedEmail(string) (bool, error)
	// Retrieves a hostname scan for a particular hostname
	GetHostnameScan(string) (checker.HostnameResult, error)
	// Enters a hostname scan.
	PutHostnameScan(string, checker.HostnameResult) error
	// Gets counts per day of hosts supporting MTA-STS adoption.
	GetMTASTSStats() (models.TimeSeries, error)
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
	"TEST_DB_NAME":    "starttls_test",
	"DB_TOKEN_TABLE":  "tokens",
	"DB_DOMAIN_TABLE": "domains",
	"DB_SCAN_TABLE":   "scans",
}

func getEnvOrDefault(varName string) string {
	envVar := os.Getenv(varName)
	if len(envVar) == 0 {
		envVar = configDefaults[varName]
	}
	return envVar
}

// LoadEnvironmentVariables loads relevant environment variables into a
// Config object.
func LoadEnvironmentVariables() (Config, error) {
	config := Config{
		Port:          getEnvOrDefault("PORT"),
		DbTokenTable:  getEnvOrDefault("DB_TOKEN_TABLE"),
		DbDomainTable: getEnvOrDefault("DB_DOMAIN_TABLE"),
		DbScanTable:   getEnvOrDefault("DB_SCAN_TABLE"),
		DbHost:        getEnvOrDefault("DB_HOST"),
		DbName:        getEnvOrDefault("DB_NAME"),
		DbUsername:    getEnvOrDefault("DB_USERNAME"),
		DbPass:        getEnvOrDefault("DB_PASSWORD"),
	}
	if flag.Lookup("test.v") != nil {
		// Avoid accidentally wiping the default db during tests.
		config.DbName = getEnvOrDefault("TEST_DB_NAME")
	}
	return config, nil
}
