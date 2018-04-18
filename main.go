package main

import (
    "log"
    "net/http"
    // "database/sql"
)

import _ "github.com/go-sql-driver/mysql"

// TODO: load these in from environment variables
const (
    PUBLIC_PORT = ":8080"
    PRIV_PORT   = ":5050"
    PRIV_KEY    = "./certs/key.pem"
    PUBLIC_KEY  = "./certs/cert.pem"
    DB_NAME     = "starttls"
    DB_USERNAME = "root"
    DB_PASSWORD = "starttls"
    DB_QUEUE_TABLE = "queue"
    DB_SCAN_TABLE = "scans"
)

func HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
    http.HandleFunc(pattern, handler)
}

func servePublicEndpoints() {
    api := API {
        database: &MemDatabase {
            domains: make(map[string]DomainData),
            scans: make(map[string][]ScanData),
            tokens: make(map[string]TokenData),
        },
    }
//     router := mux.NewRouter().StrictSlash(true)
    HandleFunc("/api/scan", api.Scan)
    HandleFunc("/api/queue", api.Queue)
    HandleFunc("/api/validate", api.Validate)
    log.Fatal(http.ListenAndServeTLS(PUBLIC_PORT, PUBLIC_KEY, PRIV_KEY, nil))
}

func main() {
    servePublicEndpoints()
}
