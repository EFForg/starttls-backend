package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	raven "github.com/getsentry/raven-go"
	"github.com/gorilla/handlers"
	"github.com/ulule/limiter"
	"github.com/ulule/limiter/drivers/middleware/stdlib"
	"github.com/ulule/limiter/drivers/store/memory"
)

func middleware(mux *http.ServeMux) http.Handler {
	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	originsOk := handlers.AllowedOrigins(allowedOrigins)

	return handlers.LoggingHandler(os.Stdout,
		recoveryHandler(
			throttleHandler(time.Minute, 10, handlers.CORS(originsOk)(mux)),
		),
	)
}

func throttleHandler(period time.Duration, limit int64, f http.Handler) http.Handler {
	if flag.Lookup("test.v") != nil {
		// Don't throttle tests
		return f
	}
	rateLimitStore := memory.NewStore()
	rate := limiter.Rate{
		Period: period,
		Limit:  limit,
	}
	rateLimiter := stdlib.NewMiddleware(limiter.New(rateLimitStore, rate,
		limiter.WithTrustForwardHeader(true)))
	return rateLimiter.Handler(f)
}

func recoveryHandler(f http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		defer func() {
			if err, ok := recover().(error); ok {
				log.Println(err)
				rvalStr := fmt.Sprint(err)
				packet := raven.NewPacket(rvalStr, raven.NewException(err.(error), raven.GetOrNewStacktrace(err.(error), 2, 3, nil)), raven.NewHttp(r))
				raven.Capture(packet, nil)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		f.ServeHTTP(w, r)
	})
}
