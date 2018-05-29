package main

import (
	"encoding/json"
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

// API is the HTTP API that this service provides.
// All requests respond with an APIResponse JSON, with fields:
// {
//     status_code // HTTP status code of request
//     message // Any error message accompanying the status_code. If 200, empty.
//     response // Response data (as JSON) from this request.
// }
// Any POST request accepts either URL query parameters or data value parameters,
// and prefers the latter if both are present.
type API struct {
	Database    db.Database
	CheckDomain checkPerformer
}

// APIResponse wraps all the responses from this API.
type APIResponse struct {
	StatusCode int         `json:"status_code"`
	Message    string      `json:"message"`
	Response   interface{} `json:"response"`
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

// Scan is the handler for /api/scan.
//   POST /api/scan
//        domain: Mail domain to scan.
//        Scans domain and returns data from it.
//   GET /api/scan?domain=<domain>
//        Retrieves most recent scan for domain.
// Both set a db.ScanData JSON as the response.
func (api API) Scan(r *http.Request) APIResponse {
	domain, err := getASCIIDomain(r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	// POST: Force scan to be conducted
	if r.Method == http.MethodPost {
		// 0. TODO: check that last scan was over an hour ago
		// 1. Conduct scan via starttls-checker
		rawScandata, err := api.CheckDomain(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		scandata := db.ScanData{
			Domain:    domain,
			Data:      rawScandata,
			Timestamp: time.Now(),
		}
		// 2. Put scan into DB
		err = api.Database.PutScan(scandata)
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

// MaxHostnames is the maximum number of hostnames that can be specified for a single domain's TLS policy.
const MaxHostnames = 8

// Extracts relevant parameters from http.Request for a POST to /api/queue
// TODO: also validate hostnames as FQDNs.
func getDomainParams(r *http.Request, domain string) (db.DomainData, error) {
	domainData := db.DomainData{Name: domain, State: db.StateUnvalidated}
	email, err := getParam("email", r)
	if err != nil {
		return domainData, err
	}
	domainData.Email = email
	domainData.MXs = make([]string, 0)
	for i := 0; i < MaxHostnames; i++ {
		field := fmt.Sprintf("hostname_%d", i)
		hostname, err := getParam(field, r)
		if err != nil {
			break
		}
		domainData.MXs = append(domainData.MXs, hostname)
	}
	if len(domainData.MXs) == 0 {
		return domainData, fmt.Errorf("No hostnames supplied for domain's TLS policy")
	}
	return domainData, nil
}

// Queue is the handler for /api/queue
//   POST /api/queue?domain=<domain>
//        domain: Mail domain to queue a TLS policy for.
//        email: Contact email associated with domain, to be verified.
//        hostname_<n>: MX hostnames to put into this domain's TLS policy. n up to 8.
//        Sets db.DomainData object as response.
//   GET  /api/queue?domain=<domain>
//        Sets db.DomainData object as response.
func (api API) Queue(r *http.Request) APIResponse {
	// Retrieve domain param
	domain, err := getASCIIDomain(r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	// POST: Insert this domain into the queue
	if r.Method == http.MethodPost {
		domainData, err := getDomainParams(r, domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
		}
		// 1. Insert domain into DB
		err = api.Database.PutDomain(domainData)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		// 2. Create token for domain
		_, err = api.Database.PutToken(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		return APIResponse{StatusCode: http.StatusOK, Response: domainData}
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

// Validate handles requests to /api/validate
//   POST /api/validate
//        token: token to validate/redeem
//        Sets the queued domain name as response.
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
		return "", fmt.Errorf("could not convert domain %s to ASCII (%s)", domain, err)
	}
	return ascii, nil
}

// Retrieves and lowercases `param` as a query parameter from `http.Request` r.
// If fails, then writes error to `http.ResponseWriter` w.
func getParam(param string, r *http.Request) (string, error) {
	unicode := r.FormValue(param)
	if unicode == "" {
		return "", fmt.Errorf("query parameter %s not specified", param)
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
