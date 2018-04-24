package main

import (
    "log"
    "net/http"

    "github.com/sydneyli/starttls-scanner/db"
)

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
