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

	"github.com/EFForg/starttls-backend/api"
	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/email"
	"github.com/EFForg/starttls-backend/policy"
	"github.com/EFForg/starttls-backend/stats"
	"github.com/EFForg/starttls-backend/util"
	"github.com/EFForg/starttls-backend/validator"

	"github.com/getsentry/raven-go"
	_ "github.com/joho/godotenv/autoload"
)

// ServePublicEndpoints serves all public HTTP endpoints.
func ServePublicEndpoints(a *api.API, cfg *db.Config) {
	mux := http.NewServeMux()
	mainHandler := a.RegisterHandlers(mux)

	portString, err := util.ValidPort(cfg.Port)
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
	emailConfig, err := email.MakeConfigFromEnv(db)
	if err != nil {
		log.Printf("couldn't connect to mailserver: %v", err)
		log.Println("======NOT SENDING EMAIL======")
	}
	list := policy.MakeUpdatedList()
	a := api.API{
		Database: db,
		List:     list,
		DontScan: loadDontScan(),
		Emailer:  emailConfig,
	}
	a.ParseTemplates()
	// if os.Getenv("VALIDATE_LIST") == "1" {
	// 	log.Println("[Starting list validator]")
	// 	go validator.ValidateRegularly("Live policy list", list, 24*time.Hour)
	// }
	if os.Getenv("VALIDATE_QUEUED") == "1" {
		v := validator.Validator{
			Name:     "testing and enforced domains",
			Store:    db.Policies,
			Interval: 24 * time.Hour,
		}
		go v.Run()
		// log.Println("[Starting queued validator]")
		// 	go validator.ValidateRegularly("MTA-STS domains", db.Policies, 24*time.Hour)
	}
	// go validator.ValidateRegularly("MTA-STS domains", db.Policies, 24*time.Hour)
	go stats.UpdateRegularly(db, time.Hour)
	ServePublicEndpoints(&a, &cfg)
}
