package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/EFForg/starttls-scanner/db"
)

func validPort(port string) (string, error) {
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("Given portstring %s is invalid.", port)
	}
	return fmt.Sprintf(":%s", port), nil
}

// ServePublicEndpoints serves all public HTTP endpoints.
func ServePublicEndpoints(api *API, cfg *db.Config) {
	http.HandleFunc("/api/scan", api.Scan)
	http.HandleFunc("/api/queue", api.Queue)
	http.HandleFunc("/api/validate", api.Validate)
	portString, err := validPort(cfg.Port)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe(portString, nil))
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
	api := API{
		Database: db,
	}
	ServePublicEndpoints(&api, &cfg)
}
