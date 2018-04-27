package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// Format string for Sql timestamps.
const SqlTimeFormat = "2006-01-02 15:04:05"

type SqlDatabase struct {
	Cfg  Config
	Conn *sql.DB
}

func InitSqlDatabase(cfg Config) (*SqlDatabase, error) {
	connectionString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		cfg.Db_username, cfg.Db_pass, cfg.Db_host, cfg.Db_name)
	fmt.Printf("Connecting to %s ... \n", connectionString)
	conn, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}
	return &SqlDatabase{Cfg: cfg, Conn: conn}, nil
}

// TOKEN DB FUNCTIONS

func (db *SqlDatabase) UseToken(token_str string) (string, error) {
	var domain string
	err := db.Conn.QueryRow("UPDATE tokens SET used=TRUE WHERE token=$1 RETURNING domain",
		token_str).Scan(&domain)
	return domain, err
}

func (db *SqlDatabase) PutToken(domain string) (TokenData, error) {
	tokenData := TokenData{
		Domain:  domain,
		Token:   randToken(),
		Expires: time.Now().Add(time.Duration(time.Hour * 72)),
		Used:    false,
	}
	_, err := db.Conn.Exec("INSERT INTO tokens(domain, token, expires) VALUES($1, $2, $3)",
		domain, tokenData.Token, tokenData.Expires.UTC().Format(SqlTimeFormat))
	if err != nil {
		return TokenData{}, err
	}
	return tokenData, nil
}

// SCAN DB FUNCTIONS

func (db *SqlDatabase) PutScan(scanData ScanData) error {
	_, err := db.Conn.Exec("INSERT INTO scans(domain, scandata, timestamp) VALUES($1, $2, $3)",
		scanData.Domain, scanData.Data, scanData.Timestamp.UTC().Format(SqlTimeFormat))
	return err
}

const mostRecentQuery = `
SELECT domain, scandata, timestamp FROM scans
    WHERE timestamp = (SELECT MAX(timestamp) FROM scans WHERE domain=$1)
`

func (db SqlDatabase) GetLatestScan(domain string) (ScanData, error) {
	scanData := ScanData{}
	err := db.Conn.QueryRow(mostRecentQuery, domain).Scan(
		&scanData.Domain, &scanData.Data, &scanData.Timestamp)
	return scanData, err
}

func (db SqlDatabase) GetAllScans(domain string) ([]ScanData, error) {
	rows, err := db.Conn.Query(
		"SELECT domain, scandata, timestamp FROM scans WHERE domain=$1", domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := []ScanData{}
	for rows.Next() {
		var scan ScanData
		if err := rows.Scan(&scan.Domain, &scan.Data, &scan.Timestamp); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

// DOMAIN DB FUNCTIONS

func (db *SqlDatabase) PutDomain(domainData DomainData) error {
	_, err := db.Conn.Exec("INSERT INTO domains(domain, email, data, status) VALUES($1, $2, $3, $4) ON CONFLICT (domain) DO UPDATE SET status=$5",
		domainData.Name, domainData.Email, "", StateUnvalidated, domainData.State)
	return err
}

func (db SqlDatabase) GetDomain(domain string) (DomainData, error) {
	data := DomainData{}
	err := db.Conn.QueryRow("SELECT domain, email, status FROM domains WHERE domain=$1",
		domain).Scan(
		&data.Name, &data.Email, &data.State)
	return data, err
}

func (db SqlDatabase) GetDomains(state DomainState) ([]DomainData, error) {
	rows, err := db.Conn.Query(
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

func tryExec(database SqlDatabase, commands []string) error {
	for _, command := range commands {
		if _, err := database.Conn.Exec(command); err != nil {
			return fmt.Errorf("The following command failed:\n%s\nWith error:\n%v",
				command, err.Error())
		}
	}
	return nil
}

// Nukes all the tables. ** Should only be used during testing **
func (db SqlDatabase) ClearTables() error {
	return tryExec(db, []string{
		fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_domain_table),
		fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_scan_table),
		fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_token_table),
		fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH 1", db.Cfg.Db_scan_table),
	})
}
