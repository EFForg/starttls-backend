package main

import (
    "log"
    "net/http"

    "github.com/sydneyli/starttls-scanner/db"
)

// Serves all public HTTP endpoints.
func ServePublicEndpoints(api *API, cfg *db.Config) {
    http.HandleFunc("/api/scan", api.Scan)
    http.HandleFunc("/api/queue", api.Queue)
    http.HandleFunc("/api/validate", api.Validate)
    log.Fatal(http.ListenAndServe(cfg.Port, nil))
}

func main() {
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
    ServePublicEndpoints(&api, &cfg)
}
