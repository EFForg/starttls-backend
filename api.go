package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/idna"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/EFForg/starttls-check/checker"
	"github.com/EFForg/starttls-scanner/db"
	"github.com/EFForg/starttls-scanner/policy"
	"github.com/getsentry/raven-go"
)

////////////////////////////////
//  *****   REST API   *****  //
////////////////////////////////

// Minimum time to cache each domain scan
const cacheScanTime = time.Minute

// Type for performing checks against an input domain. Returns
// a DomainResult object from the checker.
type checkPerformer func(API, string) (checker.DomainResult, error)

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
	List        PolicyList
	DontScan    map[string]bool
	Emailer     EmailSender
}

// PolicyList interface wraps a policy-list like structure.
// The most important query you can perform is to fetch the policy
// for a particular domain.
type PolicyList interface {
	Get(string) (policy.TLSPolicy, error)
}

// EmailSender interface wraps a back-end that can send e-mails.
type EmailSender interface {
	// SendValidation sends a validation e-mail for a particular domain,
	// with a particular validation token.
	SendValidation(*db.DomainData, string) error
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
		if response.StatusCode == http.StatusInternalServerError {
			packet := raven.NewPacket(response.Message, raven.NewHttp(r))
			raven.Capture(packet, nil)
		}
		writeJSON(w, response)
	}
}

// Checks the policy status of this domain.
func (api API) policyCheck(domain string) checker.CheckResult {
	result := checker.CheckResult{Name: "policylist"}
	if _, err := api.List.Get(domain); err == nil {
		return result.Success()
	}
	domainData, err := api.Database.GetDomain(domain)
	if err != nil {
		return result.Failure("Domain %s is not on the policy list.", domain)
	}
	if domainData.State == db.StateAdded {
		log.Println("Warning: Domain was StateAdded in DB but was not found on the policy list.")
		return result.Success()
	} else if domainData.State == db.StateQueued {
		return result.Warning("Domain %s is queued to be added to the policy list.", domain)
	} else if domainData.State == db.StateUnvalidated {
		return result.Warning("The policy addition request for %s is waiting on email validation", domain)
	}
	return result.Failure("Domain %s is not on the policy list.", domain)
}

// Performs policyCheck asynchronously.
// Should be safe since Database is safe for concurrent use, and so
// is List.
func asyncPolicyCheck(api API, domain string) <-chan checker.CheckResult {
	result := make(chan checker.CheckResult)
	go func() { result <- api.policyCheck(domain) }()
	return result
}

func defaultCheck(api API, domain string) (checker.DomainResult, error) {
	policyChan := asyncPolicyCheck(api, domain)
	result := checker.CheckDomain(domain, nil)
	result.ExtraResults = make(map[string]checker.CheckResult)
	result.ExtraResults["policylist"] = <-policyChan
	return result, nil
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
	// Check if we shouldn't scan this domain
	if api.DontScan != nil {
		if _, ok := api.DontScan[domain]; ok {
			return APIResponse{StatusCode: http.StatusTooManyRequests}
		}
	}
	// POST: Force scan to be conducted
	if r.Method == http.MethodPost {
		// 0. If last scan was recent, return cached scan.
		scan, err := api.Database.GetLatestScan(domain)
		if err == nil && time.Now().Before(scan.Timestamp.Add(cacheScanTime)) {
			return APIResponse{StatusCode: http.StatusOK, Response: scan}
		}
		// 1. Conduct scan via starttls-checker
		rawScandata, err := api.CheckDomain(api, domain)
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

	for _, hostname := range r.PostForm["hostnames"] {
		if len(hostname) == 0 {
			continue
		}
		if !validDomainName(strings.TrimPrefix(hostname, ".")) {
			return domainData, fmt.Errorf("Hostname %s is invalid", hostname)
		}
		domainData.MXs = append(domainData.MXs, hostname)
	}
	if len(domainData.MXs) == 0 {
		return domainData, fmt.Errorf("No hostnames supplied for domain's TLS policy")
	}
	if len(domainData.MXs) > MaxHostnames {
		return domainData, fmt.Errorf("No more than 8 MX hostnames are permitted")
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
		// 0. Check if scan occurred.
		scan, err := api.Database.GetLatestScan(domain)
		if err != nil {
			return APIResponse{
				StatusCode: http.StatusBadRequest,
				Message: "We haven't scanned this domain yet. " +
					"Please use the STARTTLS checker to scan your domain's " +
					"STARTTLS configuration so we can validate your submission",
			}
		}
		if scan.Data.Status != 0 {
			return APIResponse{
				StatusCode: http.StatusBadRequest,
				Message:    "%s hasn't passed our STARTTLS security checks",
			}
		}
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
		token, err := api.Database.PutToken(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}

		// 3. Send email
		err = api.Emailer.SendValidation(&domainData, token.Token)
		if err != nil {
			log.Print(err)
			return APIResponse{StatusCode: http.StatusInternalServerError,
				Message: "Unable to send validation e-mail"}
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
