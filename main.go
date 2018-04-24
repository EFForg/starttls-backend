package main

import (
    "errors"
    "log"
    "net/http"
    "os"
)

import _ "github.com/go-sql-driver/mysql"

// Default configuration values. Can be overwritten by env vars of the same name.
var configDefaults = map[string]string {
    "PORT"            : ":8080",
    "DB_NAME"         : "starttls",
    "DB_USERNAME"     : "postgres",
    "DB_PASSWORD"     : "postgres",
    "DB_TOKEN_TABLE"  : "tokens",
    "DB_DOMAIN_TABLE" : "domains",
    "DB_SCAN_TABLE"   : "scans",
}

type Config struct {
    Port             string
    Privkey          string
    Pubkey           string
    Db_name          string
    Db_username      string
    Db_pass          string
    Db_token_table   string
    Db_scan_table    string
    Db_domain_table  string
}

func getEnvOrDefault(var_name string) string {
    env_var := os.Getenv(var_name)
    if len(env_var) == 0 {
        env_var = configDefaults[var_name]
    }
    return env_var
}

func LoadEnvironmentVariables() (Config, error) {
    // Required env vars
    privkey_env := os.Getenv("PRIV_KEY")
    pubkey_env := os.Getenv("PUBLIC_KEY")
    if len(privkey_env) == 0 || len(pubkey_env) == 0 {
        return Config{}, errors.New("Environment variables PRIV_KEY and PUBLIC_KEY must be set!")
    }
    return Config {
        Port:            getEnvOrDefault("PORT"),
        Privkey:         privkey_env,
        Pubkey:          pubkey_env,
        Db_name:         getEnvOrDefault("DB_NAME"),
        Db_username:     getEnvOrDefault("DB_USERNAME"),
        Db_pass:         getEnvOrDefault("DB_PASSWORD"),
        Db_token_table:  getEnvOrDefault("DB_TOKEN_TABLE"),
        Db_domain_table: getEnvOrDefault("DB_DOMAIN_TABLE"),
        Db_scan_table:   getEnvOrDefault("DB_SCAN_TABLE"),
    }, nil
}

// Serves all public HTTPS endpoints.
func ServePublicEndpoints() {
    cfg, err := LoadEnvironmentVariables()
    if err != nil {
        log.Fatal(err)
    }
    db, err := InitSqlDatabase(cfg)
    if err != nil {
        log.Fatal(err)
    }
    api := API {
        Database: db,
    }
    http.HandleFunc("/api/scan", api.Scan)
    http.HandleFunc("/api/queue", api.Queue)
    http.HandleFunc("/api/validate", api.Validate)
    log.Fatal(http.ListenAndServeTLS(cfg.Port, cfg.Pubkey, cfg.Privkey, nil))
}

func main() {
    ServePublicEndpoints()
}
