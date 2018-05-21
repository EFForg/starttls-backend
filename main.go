package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/EFForg/starttls-scanner/db"
	"github.com/gorilla/handlers"
)

func validPort(port string) (string, error) {
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("Given portstring %s is invalid", port)
	}
	return fmt.Sprintf(":%s", port), nil
}

func registerHandlers(api *API, mux *http.ServeMux) http.Handler {
	mux.HandleFunc("/api/scan", api.Scan)
	mux.HandleFunc("/api/queue", api.Queue)
	mux.HandleFunc("/api/validate", api.Validate)

	originsOk := handlers.AllowedOrigins([]string{os.Getenv("ALLOWED_ORIGINS")})

	return handlers.RecoveryHandler()(
		handlers.CORS(originsOk)(handlers.LoggingHandler(os.Stdout, mux)),
	)
}

// ServePublicEndpoints serves all public HTTP endpoints.
func ServePublicEndpoints(api *API, cfg *db.Config) {
	mux := http.NewServeMux()
	mainHandler := registerHandlers(api, mux)
	portString, err := validPort(cfg.Port)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe(portString, mainHandler))
}

func main() {
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	db, err := db.InitSQLDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	api := API{
		Database:    db,
		CheckDomain: defaultCheck,
	}
	ServePublicEndpoints(&api, &cfg)
}
