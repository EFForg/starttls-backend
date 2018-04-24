package main

import (
    "errors"
    "log"
    "net/http"
    "os"

    "github.com/sydneyli/starttls-scanner/db"
)

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

func getEnvOrDefault(var_name string) string {
    env_var := os.Getenv(var_name)
    if len(env_var) == 0 {
        env_var = configDefaults[var_name]
    }
    return env_var
}

// Serves all public HTTPS endpoints.
func ServePublicEndpoints() {
    cfg, err := db.LoadEnvironmentVariables()
    if err != nil {
        log.Fatal(err)
    }
    db, err := db.InitSqlDatabase(cfg)
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
