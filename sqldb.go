package main

import (
    "database/sql"
    "errors"
    "fmt"
    "time"

    _ "github.com/lib/pq"
)


type SqlDatabase struct {
    Cfg Config
    Conn *sql.DB
    domains map[string]DomainData
    scans map[string][]ScanData
    tokens map[string]TokenData
}

func InitSqlDatabase(cfg Config) (*SqlDatabase, error) {
    connectionString := fmt.Sprintf("user=%s password=%s dbname=%s",
                                    cfg.Db_username, cfg.Db_pass, cfg.Db_name)
    db := &SqlDatabase {
            Cfg: cfg,
            domains: make(map[string]DomainData),
            scans: make(map[string][]ScanData),
            tokens: make(map[string]TokenData),
    }
    conn, err := sql.Open("postgres", connectionString)
    if err != nil {
        return nil, err
    }
    db.Conn = conn
    return db, nil
}

// TOKEN DB FUNCTIONS

func (db *SqlDatabase) UseToken(token_str string) error {
    _, err := db.Conn.Exec("UPDATE $1 SET used=TRUE WHERE token=$2",
                           db.Cfg.Db_token_table, token_str)
    return err
}

func (db *SqlDatabase) PutToken(domain string) (TokenData, error) {
    tokenData := TokenData {
        Domain: domain,
        Token: randToken(),
        Expires: time.Now().Add(time.Duration(time.Hour * 72)),
        Used: false,
    }
    _, err := db.Conn.Exec("INSERT INTO $1(domain, token, expires) VALUES($2, $3, $4)",
                           db.Cfg.Db_token_table,
                           domain, tokenData.Token, tokenData.Expires.Unix())
    if err != nil {
        return TokenData{}, err
    }
    return tokenData, nil
}

// SCAN DB FUNCTIONS

func (db *SqlDatabase) PutScan(scanData ScanData) error {
    _, err := db.Conn.Exec("INSERT INTO $1(domain, data) VALUES($2, $3)",
                           db.Cfg.Db_scan_table,
                           scanData.Domain, scanData.Data)
    return err
}

const mostRecentQuery = `
SELECT domain, data, timestamp FROM $1
    WHERE timestamp = (SELECT MAX(timestamp) FROM $1 WHERE domain=$2)
`

func (db SqlDatabase) GetLatestScan(domain string) (ScanData, error) {
    scanData := ScanData {}
    err := db.Conn.QueryRow(mostRecentQuery, db.Cfg.Db_scan_table).Scan(
                &scanData.Domain, &scanData.Data, &scanData.Timestamp)
    return scanData, err
}
func (db SqlDatabase) GetAllScans(domain string) ([]ScanData, error) {
    return nil, errors.New("Not implemented")
}

// DOMAIN DB FUNCTIONS

// Does this upsert correctly?
func (db *SqlDatabase) PutDomain(domainData DomainData) error {
    _, err := db.Conn.Exec("INSERT INTO $1(domain, email, state) VALUES($2, $3, $4)",
                           db.Cfg.Db_domain_table,
                           domainData.Name, domainData.Email, StateUnvalidated)
    return err
}

func (db SqlDatabase) GetDomain(domain string) (DomainData, error) {
    data := DomainData{}
    err := db.Conn.QueryRow("SELECT domain, email, state FROM $1 WHERE domain=domain",
                            db.Cfg.Db_domain_table).Scan(
                            &data.Name, &data.Email, &data.State)
    return data, err
}

func (db SqlDatabase) GetDomains(state DomainState) ([]DomainData, error) {
    return nil, errors.New("Not implemented")
}

