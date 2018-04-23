package main_test

import (
    "fmt"
    "log"
    "os"
    "testing"

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
    domain      TEXT NOT NULL PRIMARY KEY,
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
func cleanTables(db *main.SqlDatabase) error {
    return tryExec(db, []string{
        fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_domain_table),
        fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_scan_table),
        fmt.Sprintf("DELETE FROM %s", db.Cfg.Db_token_table),
        fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH 1", db.Cfg.Db_scan_table),
    })
}

var db *main.SqlDatabase

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
    err := ensureTables(db)
    if err != nil {
        log.Fatal(err)
    }
    code := m.Run()
    err = cleanTables(db)
    if err != nil {
        log.Fatal(err)
    }
    os.Exit(code)
}

