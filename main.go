package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/policy"
	"github.com/EFForg/starttls-backend/stats"
	"github.com/EFForg/starttls-backend/validator"

	"github.com/getsentry/raven-go"
	_ "github.com/joho/godotenv/autoload"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
}

func registerHandlers(api *API, mux *http.ServeMux) http.Handler {
	mux.HandleFunc("/sns", handleSESNotification(api.Database))

	mux.HandleFunc("/api/scan", api.wrapper(api.Scan))
	mux.Handle("/api/queue",
		throttleHandler(time.Hour, 20, http.HandlerFunc(api.wrapper(api.Queue))))
	mux.HandleFunc("/api/validate", api.wrapper(api.Validate))
	mux.HandleFunc("/api/stats", api.wrapper(api.Stats))
	mux.HandleFunc("/api/ping", pingHandler)

	return middleware(mux)
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
	raven.SetDSN(os.Getenv("SENTRY_URL"))

	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	db, err := db.InitSQLDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	emailConfig, err := makeEmailConfigFromEnv(db)
	if err != nil {
		log.Printf("couldn't connect to mailserver: %v", err)
		log.Println("======NOT SENDING EMAIL======")
	}
	list := policy.MakeUpdatedList()
	api := API{
		Database:    db,
		CheckDomain: defaultCheck,
		List:        list,
		DontScan:    loadDontScan(),
		Emailer:     emailConfig,
	}
	api.parseTemplates()
	if os.Getenv("VALIDATE_LIST") == "1" {
		log.Println("[Starting list validator]")
		go validator.ValidateRegularly("Live policy list", list, 24*time.Hour)
	}
	if os.Getenv("VALIDATE_QUEUED") == "1" {
		log.Println("[Starting queued validator]")
		go validator.ValidateRegularly("Testing domains", db, 24*time.Hour)
	}
	go stats.ImportRegularly(db, time.Hour)
	ServePublicEndpoints(&api, &cfg)
}
