package main_test

import (
    "fmt"
    "log"
    "os"
    "testing"
    "time"

    "."
)

const sqlCreateTokenTable = `CREATE TABLE IF NOT EXISTS %s
(
    domain      TEXT NOT NULL PRIMARY KEY,
    token       VARCHAR(255) NOT NULL,
    expires     TIMESTAMP NOT NULL,
    used        BOOLEAN DEFAULT FALSE
)
`

const sqlCreateScansTable = `CREATE TABLE IF NOT EXISTS %s
(
    id          SERIAL PRIMARY KEY,
    domain      TEXT NOT NULL,
    scandata    TEXT NOT NULL,
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
`

const sqlCreateDomainTable = `CREATE TABLE IF NOT EXISTS %s
(
    domain      TEXT NOT NULL UNIQUE PRIMARY KEY,
    email       TEXT NOT NULL,
    data        TEXT NOT NULL,
    status      VARCHAR(255) NOT NULL
)
`

func tryExec(db *main.SqlDatabase, commands []string) error {
    for _, command := range commands {
        if _, err := db.Conn.Exec(command); err != nil {
            return fmt.Errorf("The following command failed:\n%s\nWith error:\n%v",
                              command, err.Error())
        }
    }
    return nil
}

// Creates tables if they don't already exist.
func ensureTables(db *main.SqlDatabase) error {
    return tryExec(db, []string{
        fmt.Sprintf(sqlCreateDomainTable, db.Cfg.Db_domain_table),
        fmt.Sprintf(sqlCreateScansTable, db.Cfg.Db_scan_table),
        fmt.Sprintf(sqlCreateTokenTable, db.Cfg.Db_token_table),
    })
}

// Nukes all the tables.
func clearTables(db *main.SqlDatabase) error {
    return tryExec(db, []string{
        fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_domain_table),
        fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_scan_table),
        fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_token_table),
        fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH 1", db.Cfg.Db_scan_table),
    })
}

// Global database object for tests.
var db *main.SqlDatabase

// Global api object for tests (that wraps db)
var api *main.API

// Connects to local test db.
func initTestDb() *main.SqlDatabase {
    os.Setenv("PRIV_KEY", "./certs/key.pem")
    os.Setenv("PUBLIC_KEY", "./certs/cert.pem")
    cfg, err := main.LoadEnvironmentVariables()
    cfg.Db_name = fmt.Sprintf("%s_dev", cfg.Db_name)
    if err != nil {
        log.Fatal(err)
    }
    db, err := main.InitSqlDatabase(cfg)
    if err != nil {
        log.Fatal(err)
    }
    return db
}

func TestMain(m *testing.M) {
    db = initTestDb()
    api = &main.API { Database: db }
    err := ensureTables(db)
    if err != nil {
        log.Fatal(err)
    }
    go main.ServePublicEndpoints()
    code := m.Run()
    err = clearTables(db)
    if err != nil {
        log.Fatal(err)
    }
    os.Exit(code)
}

///////////////////////////
// ***** API tests ***** //
///////////////////////////

// TODO (sydli)

////////////////////////////////
// ***** Database tests ***** //
////////////////////////////////

func TestPutScan(t *testing.T) {
    clearTables(db)
    dummyScan := main.ScanData{
        Domain: "dummy.com",
        Data: "{}",
        Timestamp: time.Now(),
    }
    err := db.PutScan(dummyScan)
    if err != nil {
        t.Errorf("PutScan failed: %v\n", err)
    }
}

func TestGetLatestScan(t *testing.T) {
    clearTables(db)
    // Add two dummy objects
    earlyScan := main.ScanData{
        Domain: "dummy.com",
        Data: "test_before",
        Timestamp: time.Now(),
    }
    laterScan := main.ScanData{
        Domain: "dummy.com",
        Data: "test_after",
        Timestamp: time.Now().Add(time.Duration(time.Hour)),
    }
    err := db.PutScan(laterScan)
    if err != nil {
        t.Errorf("PutScan failed: %v\n", err)
    }
    err = db.PutScan(earlyScan)
    if err != nil {
        t.Errorf("PutScan failed: %v\n", err)
    }
    scan, err := db.GetLatestScan("dummy.com")
    if err != nil {
        t.Errorf("GetLatestScan failed: %v\n", err)
    }
    if scan.Data != "test_after" {
        t.Errorf("Expected GetLatestScan to retrieve most recent scanData: %v", scan)
    }
}

func TestGetAllScans(t *testing.T) {
    clearTables(db)
    data, err := db.GetAllScans("dummy.com")
    if err != nil {
        t.Errorf("GetAllScans failed: %v\n", err)
    }
    // Retrieving scans for domain that's never been scanned before
    if len(data) != 0 {
        t.Errorf("Expected GetAllScans to return []")
    }
    // Add two dummy objects
    dummyScan := main.ScanData{
        Domain: "dummy.com",
        Data: "test1",
        Timestamp: time.Now(),
    }
    err = db.PutScan(dummyScan)
    if err != nil {
        t.Errorf("PutScan failed: %v\n", err)
    }
    dummyScan.Data = "test2"
    err = db.PutScan(dummyScan)
    if err != nil {
        t.Errorf("PutScan failed: %v\n", err)
    }
    data, err = db.GetAllScans("dummy.com")
    // Retrieving scans for domain that's been scanned once
    if err != nil {
        t.Errorf("GetAllScans failed: %v\n", err)
    }
    if len(data) != 2 {
        t.Errorf("Expected GetAllScans to return two items, returned %d\n", len(data))
    }
    if data[0].Data != "test1" || data[1].Data != "test2" {
        t.Errorf("Expected Data of scan objects to include both test1 and test2")
    }
}

func TestPutGetDomain(t *testing.T) {
    clearTables(db)
    data := main.DomainData {
        Name: "testing.com",
        Email: "admin@testing.com",
    }
    err := db.PutDomain(data)
    if err != nil {
        t.Errorf("PutDomain failed: %v\n", err)
    }
    retrieved_data, err := db.GetDomain(data.Name)
    if err != nil {
        t.Errorf("GetDomain(%s) failed: %v\n", data.Name, err)
    }
    if retrieved_data.Name != data.Name {
        t.Errorf("Somehow, GetDomain retrieved the wrong object?")
    }
    if retrieved_data.State != main.StateUnvalidated {
        t.Errorf("Default state should be 'Unvalidated'")
    }
}

func TestUpsertDomain(t *testing.T) {
    clearTables(db)
    data := main.DomainData {
        Name: "testing.com",
        Email: "admin@testing.com",
    }
    db.PutDomain(data)
    err := db.PutDomain(main.DomainData { Name: "testing.com", State: main.StateQueued })
    if err != nil {
        t.Errorf("PutDomain(%s) failed: %v\n", data.Name, err)
    }
    retrieved_data, err := db.GetDomain(data.Name)
    if retrieved_data.State != main.StateQueued {
        t.Errorf("Expected state to be 'Queued', was %v\n", retrieved_data)
    }
}

func TestPutUseToken(t *testing.T) {
    clearTables(db)
    data, err := db.PutToken("testing.com")
    if err != nil {
        t.Errorf("PutToken failed: %v\n", err)
    }
    domain, err := db.UseToken(data.Token)
    if err != nil {
        t.Errorf("UseToken failed: %v\n", err)
    }
    if domain != data.Domain {
        t.Errorf("UseToken used token for %s instead of %s\n", domain, data.Domain)
    }
}


