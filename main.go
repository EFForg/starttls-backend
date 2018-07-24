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
	"time"

	"github.com/EFForg/starttls-scanner/db"
	"github.com/EFForg/starttls-scanner/policy"
	"github.com/getsentry/raven-go"
	"github.com/gorilla/handlers"
	"github.com/joho/godotenv"
	"github.com/ulule/limiter"
	"github.com/ulule/limiter/drivers/middleware/stdlib"
	"github.com/ulule/limiter/drivers/store/memory"
)

func validPort(port string) (string, error) {
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("portstring %s is invalid", port)
	}
	return fmt.Sprintf(":%s", port), nil
}

func throttle(period time.Duration, limit int64, f http.Handler) http.Handler {
	rateLimitStore := memory.NewStore()
	rate := limiter.Rate{
		Period: period,
		Limit:  limit,
	}
	rateLimiter := stdlib.NewMiddleware(limiter.New(rateLimitStore, rate),
		stdlib.WithForwardHeader(true))
	return rateLimiter.Handler(f)
}

func recoveryHandler(f http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		defer func() {
			if err, ok := recover().(error); ok {
				rvalStr := fmt.Sprint(err)
				packet := raven.NewPacket(rvalStr, raven.NewException(err.(error), raven.GetOrNewStacktrace(err.(error), 2, 3, nil)), raven.NewHttp(r))
				raven.Capture(packet, nil)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		f.ServeHTTP(w, r)
	})
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
}

func registerHandlers(api *API, mux *http.ServeMux) http.Handler {
	mux.HandleFunc("/api/scan", apiWrapper(api.Scan))
	// Throttle the queue endpoint more aggressively so we don't send junk e-mail.
	mux.Handle("/api/queue",
		throttle(time.Hour, 3, http.HandlerFunc(apiWrapper(api.Queue))))
	mux.HandleFunc("/api/validate", apiWrapper(api.Validate))
	mux.HandleFunc("/api/ping", pingHandler)

	originsOk := handlers.AllowedOrigins([]string{os.Getenv("ALLOWED_ORIGINS")})

	handler := recoveryHandler(
		throttle(time.Minute, 10, handlers.CORS(originsOk)(mux)),
	)
	return handlers.LoggingHandler(os.Stdout, handler)
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
	raven.SetDSN(os.Getenv("SENTRY_URL"))

	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	db, err := db.InitSQLDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	emailConfig, err := makeEmailConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	api := API{
		Database:    db,
		CheckDomain: defaultCheck,
		List:        policy.MakeUpdatedList(),
		DontScan:    loadDontScan(),
		Emailer:     emailConfig,
	}
	ServePublicEndpoints(&api, &cfg)
}
