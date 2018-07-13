package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"strings"
	"time"

	// Imports postgresql driver for database/sql
	_ "github.com/lib/pq"
)

// Format string for Sql timestamps.
const sqlTimeFormat = "2006-01-02 15:04:05"

// SQLDatabase is a Database interface backed by postgresql.
type SQLDatabase struct {
	cfg  Config  // Configuration to define the DB connection.
	conn *sql.DB // The database connection.
}

func getConnectionString(cfg Config) string {
	connectionString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		url.PathEscape(cfg.DbUsername),
		url.PathEscape(cfg.DbPass),
		url.PathEscape(cfg.DbHost),
		url.PathEscape(cfg.DbName))
	log.Println(connectionString)
	return connectionString
}

// InitSQLDatabase creates a DB connection based on information in a Config, and
// returns a pointer the resulting SQLDatabase object. If connection fails,
// returns an error.
func InitSQLDatabase(cfg Config) (*SQLDatabase, error) {
	connectionString := getConnectionString(cfg)
	log.Printf("Connecting to Postgres DB ... \n")
	conn, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}
	return &SQLDatabase{cfg: cfg, conn: conn}, nil
}

// TOKEN DB FUNCTIONS

// randToken generates a random token.
func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// UseToken sets the `used` flag on a particular email validation token to
// true, and returns the domain that was associated with the token.
func (db *SQLDatabase) UseToken(tokenStr string) (string, error) {
	var domain string
	err := db.conn.QueryRow("UPDATE tokens SET used=TRUE WHERE token=$1 AND used=FALSE RETURNING domain",
		tokenStr).Scan(&domain)
	return domain, err
}

// GetTokenByDomain gets the token for a domain name.
func (db *SQLDatabase) GetTokenByDomain(domain string) (string, error) {
	var token string
	err := db.conn.QueryRow("SELECT token FROM tokens WHERE domain=$1", domain).Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}

// PutToken generates and inserts a token into the database for a particular
// domain, and returns the resulting token row.
func (db *SQLDatabase) PutToken(domain string) (TokenData, error) {
	tokenData := TokenData{
		Domain:  domain,
		Token:   randToken(),
		Expires: time.Now().Add(time.Duration(time.Hour * 72)),
		Used:    false,
	}
	_, err := db.conn.Exec("INSERT INTO tokens(domain, token, expires) VALUES($1, $2, $3) "+
		"ON CONFLICT (domain) DO UPDATE SET token=$2, expires=$3, used=FALSE",
		domain, tokenData.Token, tokenData.Expires.UTC().Format(sqlTimeFormat))
	if err != nil {
		return TokenData{}, err
	}
	return tokenData, nil
}

// SCAN DB FUNCTIONS

// PutScan inserts a new scan for a particular domain into the database.
func (db *SQLDatabase) PutScan(scanData ScanData) error {
	byteArray, err := json.Marshal(scanData.Data)
	if err != nil {
		return err
	}
	// Serialize scanData.Data for insertion into SQLdb!
	_, err = db.conn.Exec("INSERT INTO scans(domain, scandata, timestamp) VALUES($1, $2, $3)",
		scanData.Domain, string(byteArray), scanData.Timestamp.UTC().Format(sqlTimeFormat))
	return err
}

const mostRecentQuery = `
SELECT domain, scandata, timestamp FROM scans
    WHERE timestamp = (SELECT MAX(timestamp) FROM scans WHERE domain=$1)
`

// GetLatestScan retrieves the most recent scan performed on a particular email
// domain.
func (db SQLDatabase) GetLatestScan(domain string) (ScanData, error) {
	var rawScanData []byte
	result := ScanData{}
	err := db.conn.QueryRow(mostRecentQuery, domain).Scan(
		&result.Domain, &rawScanData, &result.Timestamp)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(rawScanData, &result.Data)
	return result, err
}

// GetAllScans retrieves all the scans performed for a particular domain.
func (db SQLDatabase) GetAllScans(domain string) ([]ScanData, error) {
	rows, err := db.conn.Query(
		"SELECT domain, scandata, timestamp FROM scans WHERE domain=$1", domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := []ScanData{}
	for rows.Next() {
		var scan ScanData
		var rawScanData []byte
		if err := rows.Scan(&scan.Domain, &rawScanData, &scan.Timestamp); err != nil {
			return nil, err
		}
		err = json.Unmarshal(rawScanData, &scan.Data)
		scans = append(scans, scan)
	}
	return scans, nil
}

// DOMAIN DB FUNCTIONS

// PutDomain inserts a particular domain into the database. If the domain does
// not yet exist in the database, we initialize it with StateUnvalidated.
// Subsequent puts with the same domain updates the row with the information in
// the object provided.
func (db *SQLDatabase) PutDomain(domainData DomainData) error {
	_, err := db.conn.Exec("INSERT INTO domains(domain, email, data, status) VALUES($1, $2, $3, $4) ON CONFLICT (domain) DO UPDATE SET status=$5",
		domainData.Name, domainData.Email, strings.Join(domainData.MXs[:], ","),
		StateUnvalidated, domainData.State)
	return err
}

// GetDomain retrieves the status and information associated with a particular
// mailserver domain.
func (db SQLDatabase) GetDomain(domain string) (DomainData, error) {
	data := DomainData{}
	var rawMXs string
	err := db.conn.QueryRow("SELECT domain, email, data, status FROM domains WHERE domain=$1",
		domain).Scan(
		&data.Name, &data.Email, &rawMXs, &data.State)
	data.MXs = strings.Split(rawMXs, ",")
	return data, err
}

// GetDomains retrieves all the domains which match a particular state.
func (db SQLDatabase) GetDomains(state DomainState) ([]DomainData, error) {
	rows, err := db.conn.Query(
		"SELECT domain, email, status FROM domains WHERE status=$1", state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	domains := []DomainData{}
	for rows.Next() {
		var domain DomainData
		if err := rows.Scan(&domain.Name, &domain.Email, &domain.State); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

func tryExec(database SQLDatabase, commands []string) error {
	for _, command := range commands {
		if _, err := database.conn.Exec(command); err != nil {
			return fmt.Errorf("The following command failed:\n%s\nWith error:\n%v",
				command, err.Error())
		}
	}
	return nil
}

// ClearTables nukes all the tables. ** Should only be used during testing **
func (db SQLDatabase) ClearTables() error {
	return tryExec(db, []string{
		fmt.Sprintf("DELETE FROM %s", db.cfg.DbDomainTable),
		fmt.Sprintf("DELETE FROM %s", db.cfg.DbScanTable),
		fmt.Sprintf("DELETE FROM %s", db.cfg.DbTokenTable),
		fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH 1", db.cfg.DbScanTable),
	})
}
