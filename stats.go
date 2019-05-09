package main

import (
	"net/http"

	"github.com/EFForg/starttls-backend/stats"
)

// Stats returns statistics about MTA-STS adoption over a 14-day rolling window.
func (api API) Stats(r *http.Request) APIResponse {
	if r.Method != http.MethodGet {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed}
	}
	stats, err := stats.Get(api.Database)
	if err != nil {
		return serverError(err.Error())
	}
	return APIResponse{StatusCode: http.StatusOK, Response: stats}
}
