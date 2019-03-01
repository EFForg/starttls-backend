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

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"

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
func (db *SQLDatabase) PutToken(domain string) (models.Token, error) {
	token := models.Token{
		Domain:  domain,
		Token:   randToken(),
		Expires: time.Now().Add(time.Duration(time.Hour * 72)),
		Used:    false,
	}
	_, err := db.conn.Exec("INSERT INTO tokens(domain, token, expires) VALUES($1, $2, $3) "+
		"ON CONFLICT (domain) DO UPDATE SET token=$2, expires=$3, used=FALSE",
		domain, token.Token, token.Expires.UTC().Format(sqlTimeFormat))
	if err != nil {
		return models.Token{}, err
	}
	return token, nil
}

// SCAN DB FUNCTIONS

// PutScan inserts a new scan for a particular domain into the database.
func (db *SQLDatabase) PutScan(scan models.Scan) error {
	// Serialize scanData.Data for insertion into SQLdb!
	// @TODO marshall scan adds extra fields - need a custom obj for this
	byteArray, err := json.Marshal(scan.Data)
	if err != nil {
		return err
	}
	// Extract MTA-STS Mode to column for querying by mode, eg. adoption stats.
	// Note, this will include MTA-STS configurations that serve a parse-able
	// policy file and define a mode but don't pass full validation.
	mtastsMode := ""
	if scan.Data.MTASTSResult != nil {
		mtastsMode = scan.Data.MTASTSResult.Mode
	}
	_, err = db.conn.Exec("INSERT INTO scans(domain, scandata, timestamp, version, mta_sts_mode) VALUES($1, $2, $3, $4, $5)",
		scan.Domain, string(byteArray), scan.Timestamp.UTC().Format(sqlTimeFormat), scan.Version, mtastsMode)
	return err
}

// GetMTASTSStats returns statistics about MTA-STS adoption over a rolling
// 14-day window.
// Returns a map with
//  key: the final day of a two-week window. Windows last until EOD.
//  value: the percent of scans supporting MTA-STS in that window
func (db *SQLDatabase) GetMTASTSStats() (models.TimeSeries, error) {
	// "day" represents truncated date (ie beginning of day), but windows should
	// include the full day, so we add a day when querying timestamps.
	// Getting the most recent 31 days for now, we can set the start date to the
	// beginning of our MTA-STS data once we have some.
	query := `
		SELECT day, 100.0 * SUM(
			CASE WHEN mta_sts_mode = 'testing' THEN 1 ELSE 0 END +
			CASE WHEN mta_sts_mode = 'enforce' THEN 1 ELSE 0 END
		) / COUNT(day) as percent
		FROM (
				SELECT date_trunc('day', d)::date AS day
				FROM generate_series(CURRENT_DATE-31, CURRENT_DATE, '1 day'::INTERVAL) d )
		AS days
		INNER JOIN LATERAL (
				SELECT DISTINCT ON (domain) domain, timestamp, mta_sts_mode
				FROM scans
				WHERE timestamp BETWEEN day - '13 days'::INTERVAL AND day + '1 day'::INTERVAL
				ORDER BY domain, timestamp DESC
			) AS most_recent_scans ON TRUE
		GROUP BY day;`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ts := make(map[time.Time]float32)
	for rows.Next() {
		var t time.Time
		var count float32
		if err := rows.Scan(&t, &count); err != nil {
			return nil, err
		}
		ts[t.UTC()] = count
	}
	return ts, nil
}

const mostRecentQuery = `
SELECT domain, scandata, timestamp, version FROM scans
    WHERE timestamp = (SELECT MAX(timestamp) FROM scans WHERE domain=$1)
`

// GetLatestScan retrieves the most recent scan performed on a particular email
// domain.
func (db SQLDatabase) GetLatestScan(domain string) (models.Scan, error) {
	var rawScanData []byte
	result := models.Scan{}
	err := db.conn.QueryRow(mostRecentQuery, domain).Scan(
		&result.Domain, &rawScanData, &result.Timestamp, &result.Version)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(rawScanData, &result.Data)
	return result, err
}

// GetAllScans retrieves all the scans performed for a particular domain.
func (db SQLDatabase) GetAllScans(domain string) ([]models.Scan, error) {
	rows, err := db.conn.Query(
		"SELECT domain, scandata, timestamp, version FROM scans WHERE domain=$1", domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := []models.Scan{}
	for rows.Next() {
		var scan models.Scan
		var rawScanData []byte
		if err := rows.Scan(&scan.Domain, &rawScanData, &scan.Timestamp, &scan.Version); err != nil {
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
func (db *SQLDatabase) PutDomain(domain models.Domain) error {
	_, err := db.conn.Exec("INSERT INTO domains(domain, email, data, status) "+
		"VALUES($1, $2, $3, $4) "+
		"ON CONFLICT (domain) DO UPDATE SET status=$5",
		domain.Name, domain.Email, strings.Join(domain.MXs[:], ","),
		models.StateUnvalidated, domain.State)
	return err
}

// GetDomain retrieves the status and information associated with a particular
// mailserver domain.
func (db SQLDatabase) GetDomain(domain string) (models.Domain, error) {
	data := models.Domain{}
	var rawMXs string
	err := db.conn.QueryRow("SELECT domain, email, data, status, last_updated FROM domains WHERE domain=$1",
		domain).Scan(
		&data.Name, &data.Email, &rawMXs, &data.State, &data.LastUpdated)
	data.MXs = strings.Split(rawMXs, ",")
	if len(rawMXs) == 0 {
		data.MXs = []string{}
	}
	return data, err
}

// GetDomains retrieves all the domains which match a particular state.
func (db SQLDatabase) GetDomains(state models.DomainState) ([]models.Domain, error) {
	rows, err := db.conn.Query(
		"SELECT domain, email, data, status, last_updated FROM domains WHERE status=$1", state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	domains := []models.Domain{}
	for rows.Next() {
		var domain models.Domain
		var rawMXs string
		if err := rows.Scan(&domain.Name, &domain.Email, &rawMXs, &domain.State, &domain.LastUpdated); err != nil {
			return nil, err
		}
		domain.MXs = strings.Split(rawMXs, ",")
		domains = append(domains, domain)
	}
	return domains, nil
}

// EMAIL BLACKLIST DB FUNCTIONS

// PutBlacklistedEmail adds a bounce or complaint notification to the email blacklist.
func (db SQLDatabase) PutBlacklistedEmail(email string, reason string, timestamp string) error {
	_, err := db.conn.Exec("INSERT INTO blacklisted_emails(email, reason, timestamp) VALUES($1, $2, $3)",
		email, reason, timestamp)
	return err
}

// IsBlacklistedEmail returns true iff we've blacklisted the passed email address for sending.
func (db SQLDatabase) IsBlacklistedEmail(email string) (bool, error) {
	var count int
	row := db.conn.QueryRow("SELECT COUNT(*) FROM blacklisted_emails WHERE email=$1", email)
	err := row.Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func tryExec(database SQLDatabase, commands []string) error {
	for _, command := range commands {
		if _, err := database.conn.Exec(command); err != nil {
			return fmt.Errorf("command failed: %s\nwith error: %v",
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
		fmt.Sprintf("DELETE FROM %s", "hostname_scans"),
		fmt.Sprintf("DELETE FROM %s", "blacklisted_emails"),
		fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH 1", db.cfg.DbScanTable),
	})
}

// DomainsToValidate [interface Validator] retrieves domains from the
// DB whose policies should be validated.
func (db SQLDatabase) DomainsToValidate() ([]string, error) {
	domains := []string{}
	data, err := db.GetDomains(models.StateQueued)
	if err != nil {
		return domains, err
	}
	for _, domainInfo := range data {
		domains = append(domains, domainInfo.Name)
	}
	return domains, nil
}

// HostnamesForDomain [interface Validator] retrieves the hostname policy for
// a particular domain.
func (db SQLDatabase) HostnamesForDomain(domain string) ([]string, error) {
	data, err := db.GetDomain(domain)
	if err != nil {
		return []string{}, err
	}
	return data.MXs, nil
}

// GetName retrieves a readable name for this data store (for use in error messages)
func (db SQLDatabase) GetName() string {
	return "SQL Database"
}

// GetHostnameScan retrives most recent scan from database.
func (db *SQLDatabase) GetHostnameScan(hostname string) (checker.HostnameResult, error) {
	result := checker.HostnameResult{
		Hostname: hostname,
		Result:   &checker.Result{},
	}
	var rawScanData []byte
	err := db.conn.QueryRow(`SELECT timestamp, status, scandata FROM hostname_scans
                    WHERE hostname=$1 AND
                    timestamp=(SELECT MAX(timestamp) FROM hostname_scans WHERE hostname=$1)`,
		hostname).Scan(&result.Timestamp, &result.Status, &rawScanData)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(rawScanData, &result.Checks)
	return result, err
}

// PutHostnameScan puts this scan into the database.
func (db *SQLDatabase) PutHostnameScan(hostname string, result checker.HostnameResult) error {
	data, err := json.Marshal(result.Checks)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`INSERT INTO hostname_scans(hostname, status, scandata)
                                VALUES($1, $2, $3)`, hostname, result.Status, string(data))
	return err
}

func (db *SQLDatabase) PutDomainTotals(totals checker.DomainTotals) error {
	_, err := db.conn.Exec("INSERT INTO domain_totals(time, source, attempted, connected, mta_sts_testing, mta_sts_enforce) VALUES($1, $2, $3, $4, $5, $6)",
		totals.Time, totals.Source, totals.Attempted, totals.Connected, len(totals.MTASTSTesting), len(totals.MTASTSEnforce))
	return err
}
