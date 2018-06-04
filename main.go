package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/EFForg/starttls-scanner/db"
	"github.com/EFForg/starttls-scanner/policy"
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

	server := http.Server{
		Addr:    portString,
		Handler: mainHandler,
	}

	exited := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(exited)
	}()

	log.Fatal(server.ListenAndServe())
	<-exited
}

// Loads a map of domains (effectively a set for fast lookup) to blacklist.
// if `DOMAIN_BLACKLIST` is not set, returns an empty map.
func loadDontScan() map[string]bool {
	filepath := os.Getenv("DOMAIN_BLACKLIST")
	if len(filepath) == 0 {
		return make(map[string]bool)
	}
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
		List:        policy.MakeUpdatedList(),
		DontScan:    loadDontScan(),
	}
	ServePublicEndpoints(&api, &cfg)
}
