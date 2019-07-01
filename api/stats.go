package api

import (
	"net/http"

	"github.com/EFForg/starttls-backend/stats"
)

// Stats returns statistics about MTA-STS adoption over a 14-day rolling window.
func (api API) stats(r *http.Request) response {
	if r.Method != http.MethodGet {
		return response{StatusCode: http.StatusMethodNotAllowed}
	}
	stats, err := stats.Get(api.Database)
	if err != nil {
		return serverError(err.Error())
	}
	return response{StatusCode: http.StatusOK, Response: stats}
}
