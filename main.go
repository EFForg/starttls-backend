package main

import (
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    // "database/sql"
)

import _ "github.com/go-sql-driver/mysql"

// Default configuration values
const (
    PUBLIC_PORT = ":8080"
    DB_NAME     = "starttls"
    DB_USERNAME = "root"
    DB_PASSWORD = "starttls"
    DB_QUEUE_TABLE = "queue"
    DB_SCAN_TABLE = "scans"
)

type Config struct {
    Port             string
    Privkey          string
    Pubkey           string
    Db_name          string
    Db_username      string
    Db_pass          string
    Db_queue_table   string
    Db_scan_table    string
    Db_domain_table  string
}

func getEnvOrDefault(env_name string, default_ string) string {
    env_var := os.Getenv(env_name)
    if len(env_var) == 0 {
        env_var = default_
    }
    return env_var
}

func loadEnvironmentVariables() (Config, error) {
    privkey_env := os.Getenv("PRIV_KEY")
    pubkey_env := os.Getenv("PUBLIC_KEY")
    if len(privkey_env) == 0 || len(pubkey_env) == 0 {
        return Config{}, errors.New("Environment variables PRIV_KEY and PUBLIC_KEY must be set!")
    }
    return Config {
        Port:           getEnvOrDefault("PORT", PUBLIC_PORT),
        Privkey:        privkey_env,
        Pubkey:         pubkey_env,
        Db_name:        getEnvOrDefault("DB_NAME", DB_NAME),
        Db_username:    getEnvOrDefault("DB_USERNAME", DB_USERNAME),
        Db_pass:        getEnvOrDefault("DB_PASSWORD", DB_PASSWORD),
        Db_queue_table: getEnvOrDefault("DB_QUEUE_TABLE", DB_QUEUE_TABLE),
        Db_scan_table:  getEnvOrDefault("DB_SCAN_TABLE", DB_SCAN_TABLE),
    }, nil
}

// Serves all public HTTPS endpoints.
func servePublicEndpoints() {
    cfg, err := loadEnvironmentVariables()
    if err != nil {
        fmt.Println(err)
        return
    }
    api := API {
        database: &MemDatabase {
            domains: make(map[string]DomainData),
            scans: make(map[string][]ScanData),
            tokens: make(map[string]TokenData),
        },
    }
    http.HandleFunc("/api/scan", api.Scan)
    http.HandleFunc("/api/queue", api.Queue)
    http.HandleFunc("/api/validate", api.Validate)
    log.Fatal(http.ListenAndServeTLS(cfg.Port, cfg.Pubkey, cfg.Privkey, nil))
}

func main() {
    servePublicEndpoints()
}
