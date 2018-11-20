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
	"gopkg.in/gorp.v2"
)

// Format string for Sql timestamps.
const sqlTimeFormat = "2006-01-02 15:04:05"

// SQLDatabase is a Database interface backed by postgresql.
type SQLDatabase struct {
	cfg  Config // Configuration to define the DB connection.
	conn *gorp.DbMap
	// conn *sql.DB // The database connection.
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
	dbmap := &gorp.DbMap{Db: conn, Dialect: gorp.PostgresDialect{}}
	dbmap.AddTableWithName(DomainData{}, "domains").SetKeys(false, "Name")
	dbmap.AddTableWithName(TokenData{}, "tokens").SetKeys(false, "Domain")
	dbmap.AddTableWithName(ScanData{}, "scans").SetKeys(true, "ID")
	dbmap.AddTableWithName(EmailBlacklistData{}, "blacklisted_emails").SetKeys(true, "ID")
	return &SQLDatabase{cfg: cfg, conn: dbmap}, nil
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
	obj, err := db.conn.Get(TokenData{}, domain)
	return obj.(*TokenData).Token, err
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
	err := db.conn.Insert(&tokenData)
	if err != nil {
		_, err = db.conn.Update(&tokenData)
	}
	return tokenData, err
}

// SCAN DB FUNCTIONS

// PreInsert marshals Data into DataBlob
func (d *ScanData) PreInsert(s gorp.SqlExecutor) error {
	byteArray, err := json.Marshal(d.Data)
	if err != nil {
		return err
	}
	d.DataBlob = string(byteArray)
	return nil
}

// PostGet unmarshals DataBlob into Data
func (d *ScanData) PostGet(s gorp.SqlExecutor) error {
	err := json.Unmarshal([]byte(d.DataBlob), &(d.Data))
	return err
}

// PutScan inserts a new scan for a particular domain into the database.
func (db *SQLDatabase) PutScan(scanData ScanData) error {
	return db.conn.Insert(&scanData)
}

const mostRecentQuery = `
SELECT domain, scandata, timestamp FROM scans
    WHERE timestamp = (SELECT MAX(timestamp) FROM scans WHERE domain=$1)
`

// GetLatestScan retrieves the most recent scan performed on a particular email
// domain.
func (db SQLDatabase) GetLatestScan(domain string) (ScanData, error) {
	var result ScanData
	err := db.conn.SelectOne(&result, mostRecentQuery, domain)
	return result, err
}

// GetAllScans retrieves all the scans performed for a particular domain.
func (db SQLDatabase) GetAllScans(domain string) ([]ScanData, error) {
	// PostGet is only called if the slice elements are pointers
	// https://github.com/go-gorp/gorp/issues/338
	scanPtrs := []*ScanData{}
	_, err := db.conn.Select(&scanPtrs, "select * from scans where domain=$1", domain)
	scans := []ScanData{}
	for _, scan := range scanPtrs {
		scans = append(scans, *scan)
	}
	return scans, err
}

// DOMAIN DB FUNCTIONS

// PreUpdate dumps structured data into a blob for SQL
func (d *DomainData) PreUpdate(s gorp.SqlExecutor) error {
	d.Data = strings.Join(d.MXs[:], ",")
	return nil
}

// PreInsert does the same thing as PreUpdate and also sets
// default state to Unvalidated
func (d *DomainData) PreInsert(s gorp.SqlExecutor) error {
	if len(d.State) == 0 {
		d.State = StateUnvalidated
	}
	return d.PreUpdate(s)
}

// PostGet retrives structured MX data from d.Data
func (d *DomainData) PostGet(s gorp.SqlExecutor) error {
	d.MXs = []string{}
	if len(d.Data) > 0 {
		d.MXs = strings.Split(d.Data, ",")
	}
	return nil
}

func (d *DomainData) equal(other *DomainData) bool {
	mxsSame := len(d.MXs) == len(other.MXs)
	for i := range d.MXs {
		mxsSame = mxsSame && d.MXs[i] == other.MXs[i]
	}
	return d.Email == other.Email && mxsSame
}

// PutDomain inserts a particular domain into the database. If the domain does
// not yet exist in the database, we initialize it with StateUnvalidated.
// Subsequent puts with the same domain updates the row with the information in
// the object provided.
func (db *SQLDatabase) PutDomain(domainData DomainData) error {
	_, err := db.conn.Exec("INSERT INTO domains(domain, email, data, status) "+
		"VALUES($1, $2, $3, $4) "+
		"ON CONFLICT (domain) DO UPDATE SET status=$5",
		domainData.Name, domainData.Email, strings.Join(domainData.MXs[:], ","),
		StateUnvalidated, domainData.State)
	return err
}

// GetDomain retrieves the status and information associated with a particular
// mailserver domain.
func (db SQLDatabase) GetDomain(domain string) (DomainData, error) {
	obj, err := db.conn.Get(DomainData{}, domain)
	if obj == nil {
		return DomainData{}, err
	}
	return *(obj.(*DomainData)), err
}

// GetDomains retrieves all the domains which match a particular state.
func (db SQLDatabase) GetDomains(state DomainState) ([]DomainData, error) {
	domainData := []*DomainData{}
	_, err := db.conn.Select(&domainData, "select * from domains where status=$1", state)
	domains := []DomainData{}
	for _, domain := range domainData {
		domains = append(domains, *domain)
	}
	return domains, err
}

// EMAIL BLACKLIST DB FUNCTIONS

// PutBlacklistedEmail adds a bounce or complaint notification to the email blacklist.
func (db SQLDatabase) PutBlacklistedEmail(email string, reason string, timestamp string) error {
	return db.conn.Insert(&EmailBlacklistData{
		Email: email, Timestamp: timestamp, Reason: reason,
	})
}

// IsBlacklistedEmail returns true iff we've blacklisted the passed email address for sending.
func (db SQLDatabase) IsBlacklistedEmail(email string) (bool, error) {
	count, err := db.conn.SelectInt("select count(*) from blacklisted_emails where email=$1", email)
	return count > 0, err
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
		fmt.Sprintf("DELETE FROM %s", "blacklisted_emails"),
		fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH 1", db.cfg.DbScanTable),
	})
}

// DomainsToValidate [interface Validator] retrieves domains from the
// DB whose policies should be validated.
func (db SQLDatabase) DomainsToValidate() ([]string, error) {
	domains := []string{}
	data, err := db.GetDomains(StateQueued)
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
