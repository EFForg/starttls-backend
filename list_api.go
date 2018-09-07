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
//       EXTRA PARAM FOR MANUAL VALIDATION:
//       filename:     What filename to read the CSVs from
func (api API) GetList(r *http.Request) APIResponse {
	expireWeeks := getNumberParam(r, "expire_weeks", 2)
	// queuedWeeks := getNumberParam(r, "queued_weeks", 1)
	filename, _ := getParam("filename", r)
	list := policy.List{Policies: make(map[string]policy.TLSPolicy)}
	list.Timestamp = time.Now()
	list.Expires = list.Timestamp.Add(time.Hour * 24 * 7 * time.Duration(expireWeeks))

	queued, err := readFromCSV(filename)
	// queued, err := api.Database.GetDomains(db.StateQueued)
	if err != nil {
		return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}
	// cutoffTime := time.Now().Add(-time.Hour * 24 * 7 * time.Duration(queuedWeeks))
	for _, domainData := range queued {
		// if domainData.LastUpdated.After(cutoffTime) {
		// 	continue
		// }
		if _, err = api.List.Get(domainData.Name); err != nil {
			list.Add(domainData.Name, policy.TLSPolicy{
				Mode: "testing",
				MXs:  domainData.MXs,
			})
		}
	}
	return APIResponse{StatusCode: http.StatusOK, Response: list}
}

// SyncList manually syncs the list state into the database state.
func (api API) SyncList(r *http.Request) APIResponse {
	list := api.List.Raw()
	queued, err := api.Database.GetDomains(db.StateQueued)
	if err != nil {
		return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}
	advance := []string{}
	for _, domainData := range queued {
		if _, ok := list.Policies[domainData.Name]; ok {
			advance = append(advance, domainData.Name)
		}
	}
	for _, domain := range advance {
		api.Database.PutDomain(db.DomainData{
			Name:  domain,
			State: db.StateAdded,
		})
	}
	return APIResponse{StatusCode: http.StatusOK}
}
