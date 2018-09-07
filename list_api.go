package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/policy"
)

////////////////////////////////
//  *****   LIST API   *****  //
////////////////////////////////

func getNumberParam(r *http.Request, paramName string, defaultNumber int) int {
	numStr, err := getParam(paramName, r)
	result := defaultNumber
	if err == nil {
		if n, err := strconv.Atoi(numStr); err == nil {
			result = n
		}
	}
	return result
}

// GetList generates a new JSON file, with all queued entries!
//   GET /auth/list
//       expire_weeks: after how many weeks should this list expire? If unset
//                     or invalid, defaults to 2. If set to 0, expires immediately.
//       queued_weeks: for at least how many weeks should domains on the resulting list
//                     have been queued? if unset or invalid, defaults to 1.
func (api API) GetList(r *http.Request) APIResponse {
	expireWeeks := getNumberParam(r, "expire_weeks", 2)
	queuedWeeks := getNumberParam(r, "queued_weeks", 1)
	list := api.List.Raw()
	list.Timestamp = time.Now()
	list.Expires = list.Timestamp.Add(time.Hour * 24 * 7 * time.Duration(expireWeeks))
	queued, err := api.Database.GetDomains(db.StateQueued)
	if err != nil {
		return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}
	cutoffTime := time.Now().Add(-time.Hour * 24 * 7 * time.Duration(queuedWeeks))
	for _, domainData := range queued {
		if domainData.LastUpdated.After(cutoffTime) {
			continue
		}
		list.Add(domainData.Name, policy.TLSPolicy{
			Mode: "enforce",
			MXs:  domainData.MXs,
		})
	}
	return APIResponse{StatusCode: http.StatusOK, Response: list}
}

// POST /auth/fail?domain=<domain>
func (api API) FailDomain(r *http.Request) APIResponse {
	if r.Method != http.MethodPost {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/auth/fail only accepts POST requests"}
	}
	domain, err := getParam("domain", r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: "parameter domain is required"}
	}
	if _, err := api.Database.GetDomain(domain); err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: "domain " + domain + " not in database"}
	}
	err = api.Database.PutDomain(db.DomainData{
		Name:  domain,
		State: db.StateFailed,
	})
	if err != nil {
		return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}
	return APIResponse{StatusCode: http.StatusOK}
}
