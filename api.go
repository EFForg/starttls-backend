package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/idna"
	"net/http"
	"strings"
	"time"

	"github.com/EFForg/starttls-scanner/db"
	"github.com/sydneyli/starttls-check/checker"
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

func defaultCheck(domain string) (string, error) {
	// false and true specify which of the checks we'd like to perform--
	// Only STARTTLS but not MTASTS.
	return checker.PerformChecksJSON(domain, false, true)
}

// Scan allows GET or POST /api/scan?domain=abc.com
func (api API) Scan(w http.ResponseWriter, r *http.Request) {
	domain, ok := getASCIIDomain(w, r)
	if !ok {
		return
	}
	// POST: Force scan to be conducted
	if r.Method == http.MethodPost {
		// 0. TODO: check that last scan was over an hour ago
		// 1. Conduct scan via starttls-checker
		scandata, err := api.CheckDomain(domain)
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		// 2. Put scan into DB
		err = api.Database.PutScan(db.ScanData{
			Domain:    domain,
			Data:      scandata,
			Timestamp: time.Now(),
		})
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		// 3. TODO: Return scandata as JSON (also set response type)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprintf(w, "%s\n", scandata)
		w.WriteHeader(200)
		// GET: Just fetch the most recent scan
	} else if r.Method == http.MethodGet {
		scan, err := api.Database.GetLatestScan(domain)
		if err != nil {
			http.Error(w, "No scans found!", http.StatusNotFound)
			return
		}
		writeJSON(w, scan)
	} else {
		http.Error(w, "/api/queue only accepts POST and GET requests",
			http.StatusMethodNotAllowed)
	}
}

// Queue allows GET or POST /api/queue?domain=abc.com
func (api API) Queue(w http.ResponseWriter, r *http.Request) {
	// Retrieve domain param
	domain, ok := getASCIIDomain(w, r)
	if !ok {
		return
	}

	// POST: Insert this domain into the queue
	if r.Method == http.MethodPost {
		email, ok := getParam("email", w, r)
		if !ok {
			return
		}
		// 1. Insert domain into DB
		err := api.Database.PutDomain(db.DomainData{
			Name:  domain,
			Email: email,
			State: db.StateUnvalidated,
		})
		if err != nil {
			http.Error(w, "Internal server error",
				http.StatusInternalServerError)
			return
		}
		// 2. Create token for domain
		token, err := api.Database.PutToken(domain)
		if err != nil {
			http.Error(w, fmt.Sprintf("Something happened %s", err), // TODO
				http.StatusInternalServerError)
			return
		}
		writeJSON(w, token)

		// GET: Retrieve domain status from queue
	} else if r.Method == http.MethodGet {
		status, err := api.Database.GetDomain(domain)
		if err != nil {
			http.Error(w, "No domains found!", http.StatusNotFound)
			return
		}
		writeJSON(w, status)
	} else {
		http.Error(w, "/api/queue only accepts POST and GET requests",
			http.StatusMethodNotAllowed)
	}
}

// Validate allows POST /api/validate?token=xyz
func (api API) Validate(w http.ResponseWriter, r *http.Request) {
	token, ok := getParam("token", w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "/api/validate only accepts POST requests",
			http.StatusMethodNotAllowed)
		return
	}
	// 1. Use the token
	domain, err := api.Database.UseToken(token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Could not use token %s (%s)", token, err),
			http.StatusBadRequest)
		return
	}
	// 2. Update domain status from "UNVALIDATED" to "QUEUED"
	domainData, err := api.Database.GetDomain(domain)
	if err != nil {
		http.Error(w, "Could not find associated domain!", http.StatusInternalServerError)
		return
	}
	err = api.Database.PutDomain(db.DomainData{
		Name:  domainData.Name,
		Email: domainData.Email,
		State: db.StateQueued,
	})
	if err != nil {
		http.Error(w, "Could not update domain status!", http.StatusInternalServerError)
		return
	}
	writeJSON(w, domain)
}

// Retrieve "domain" parameter from request as ASCII
// If fails, then writes error to `http.ResponseWriter` w.
func getASCIIDomain(w http.ResponseWriter, r *http.Request) (string, bool) {
	domain, ok := getParam("domain", w, r)
	if !ok {
		return domain, ok
	}
	ascii, err := idna.ToASCII(domain)
	if err != nil {

		http.Error(w, fmt.Sprintf("Could not convert domain %s to ASCII (%s)", domain, err),
			http.StatusInternalServerError)
		return "", false
	}
	return ascii, true
}

// Retrieves and lowercases `param` as a query parameter from `http.Request` r.
// If fails, then writes error to `http.ResponseWriter` w.
func getParam(param string, w http.ResponseWriter, r *http.Request) (string, bool) {
	unicode := r.FormValue(param)
	if unicode == "" {
		http.Error(w, fmt.Sprintf("Query parameter %s not specified", param),
			http.StatusBadRequest)
		return "", false
	}
	return strings.ToLower(unicode), true
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
