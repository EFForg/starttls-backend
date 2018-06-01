package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
