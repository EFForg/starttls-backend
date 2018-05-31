package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/EFForg/starttls-scanner/db"
	"github.com/gorilla/handlers"
	"github.com/joho/godotenv"
)

func validPort(port string) (string, error) {
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("Given portstring %s is invalid", port)
	}
	return fmt.Sprintf(":%s", port), nil
}

func registerHandlers(api *API, mux *http.ServeMux) http.Handler {
	mux.HandleFunc("/api/scan", apiWrapper(api.Scan))
	mux.HandleFunc("/api/queue", apiWrapper(api.Queue))
	mux.HandleFunc("/api/validate", apiWrapper(api.Validate))

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

func loadDontScan() map[string]bool {
	filepath := os.Getenv("DOMAIN_BLACKLIST")
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Fatal(err)
	}
	domainlist := strings.Split(string(data), "\n")
	domainset := make(map[string]bool)
	for _, domain := range domainlist {
		if len(domain) > 0 {
			domainset[domain] = true
		}
	}
	return domainset
}

func main() {
	godotenv.Load()
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
		DontScan:    loadDontScan(),
	}
	ServePublicEndpoints(&api, &cfg)
}
