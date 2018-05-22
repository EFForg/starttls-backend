package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"net/http"
	"strings"
	"time"

	"github.com/EFForg/starttls-check/checker"
	"github.com/EFForg/starttls-scanner/db"
)

////////////////////////////////
//  *****   REST API   *****  //
////////////////////////////////

// Type for performing checks against an input domain. Returns
// a JSON-formatted string.
type checkPerformer func(string) (string, error)

// API is the HTTP API that this service provides. In particular:
// Scan:
//   POST /api/scan?domain=<domain>
//        returns scanData (JSON blob from starttls-check)
// Queue:
//   POST /api/queue?domain=<domain>
//        returns {token: <token>}
//   GET  /api/queue?domain=<domain>
//        returns domainData
// Validate:
//   POST /api/validate?token=<token>
//        returns OK
type API struct {
	Database    db.Database
	CheckDomain checkPerformer
}

type APIResponse struct {
	StatusCode int
	Message    string
	Response   interface{}
}

type apiHandler func(r *http.Request) APIResponse

func apiWrapper(api apiHandler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		response := api(r)
		if response.StatusCode != http.StatusOK {
			http.Error(w, response.Message, response.StatusCode)
		}
		writeJSON(w, response)
	}
}

func defaultCheck(domain string) (string, error) {
	result := checker.CheckDomain(domain, nil)
	byteArray, err := json.Marshal(result)
	return string(byteArray), err
}

// Scan allows GET or POST /api/scan?domain=abc.com
func (api API) Scan(r *http.Request) APIResponse {
	domain, err := getASCIIDomain(r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	// POST: Force scan to be conducted
	if r.Method == http.MethodPost {
		// 0. TODO: check that last scan was over an hour ago
		// 1. Conduct scan via starttls-checker
		scandata, err := api.CheckDomain(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		// 2. Put scan into DB
		err = api.Database.PutScan(db.ScanData{
			Domain:    domain,
			Data:      scandata,
			Timestamp: time.Now(),
		})
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		// 3. TODO: Return scandata as JSON (also set response type)
		return APIResponse{StatusCode: http.StatusOK, Response: scandata}
		// GET: Just fetch the most recent scan
	} else if r.Method == http.MethodGet {
		scan, err := api.Database.GetLatestScan(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusNotFound, Message: err.Error()}
		}
		return APIResponse{StatusCode: http.StatusOK, Response: scan}
	} else {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/scan only accepts POST and GET requests"}
	}
}

// Queue allows GET or POST /api/queue?domain=abc.com
func (api API) Queue(r *http.Request) APIResponse {
	// Retrieve domain param
	domain, err := getASCIIDomain(r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	// POST: Insert this domain into the queue
	if r.Method == http.MethodPost {
		email, err := getParam("email", r)
		if err != nil {
			return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
		}
		// 1. Insert domain into DB
		err = api.Database.PutDomain(db.DomainData{
			Name:  domain,
			Email: email,
			State: db.StateUnvalidated,
		})
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		// 2. Create token for domain
		token, err := api.Database.PutToken(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		return APIResponse{StatusCode: http.StatusOK, Response: token}
		// GET: Retrieve domain status from queue
	} else if r.Method == http.MethodGet {
		status, err := api.Database.GetDomain(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusNotFound, Message: err.Error()}
		}
		return APIResponse{StatusCode: http.StatusOK, Response: status}
	} else {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/queue only accepts POST and GET requests"}
	}
}

// Validate allows POST /api/validate?token=xyz
func (api API) Validate(r *http.Request) APIResponse {
	token, err := getParam("token", r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	if r.Method != http.MethodPost {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/validate only accepts POST requests"}
	}
	// 1. Use the token
	domain, err := api.Database.UseToken(token)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	// 2. Update domain status from "UNVALIDATED" to "QUEUED"
	domainData, err := api.Database.GetDomain(domain)
	if err != nil {
		return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}
	err = api.Database.PutDomain(db.DomainData{
		Name:  domainData.Name,
		Email: domainData.Email,
		State: db.StateQueued,
	})
	if err != nil {
		return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}
	return APIResponse{StatusCode: http.StatusOK, Response: domain}
}

// Retrieve "domain" parameter from request as ASCII
// If fails, returns an error.
func getASCIIDomain(r *http.Request) (string, error) {
	domain, err := getParam("domain", r)
	if err != nil {
		return domain, err
	}
	ascii, err := idna.ToASCII(domain)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Could not convert domain %s to ASCII (%s)", domain, err))
	}
	return ascii, nil
}

// Retrieves and lowercases `param` as a query parameter from `http.Request` r.
// If fails, then writes error to `http.ResponseWriter` w.
func getParam(param string, r *http.Request) (string, error) {
	unicode := r.FormValue(param)
	if unicode == "" {
		return "", errors.New(fmt.Sprintf("Query parameter %s not specified", param))
	}
	return strings.ToLower(unicode), nil
}

// Writes `v` as a JSON object to http.ResponseWriter `w`. If an error
// occurs, writes `http.StatusInternalServerError` to `w`.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		msg := fmt.Sprintf("Internal error: could not format JSON. (%s)\n", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s\n", b)
}
