package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/EFForg/starttls-scanner/db"
)

// Workflow tests against REST API.
// TODO: Mock starttls-scanner/check so we don't actually make check requests

var api *API

// Load env. vars, initialize DB hook, and tests API
func TestMain(m *testing.M) {
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	// Note: we can use either MemDatabase or SqlDatabase here, should not make a difference.
	// db, err := db.InitSqlDatabase(cfg)
	// if err != nil {
	//     log.Fatal(err)
	// }
	api = &API{
		Database: db.InitMemDatabase(cfg),
	}
	code := m.Run()
	api.Database.ClearTables()
	os.Exit(code)
}

func TestInvalidPort(t *testing.T) {
	portString, err := validPort("8000")
	if err != nil {
		t.Errorf("Should not have errored on valid string: %v", err)
		return
	}
	if portString != ":8000" {
		t.Errorf("Expected portstring be :8000 instead of %s", portString)
		return
	}
	portString, err = validPort("80a")
	if err == nil {
		t.Errorf("Expected error on invalid port")
		return
	}
}

func TestPanicRecovery(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Expected server to handle panic")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/panic", panickingHandler)
	server := httptest.NewServer(registerHandlers(api, mux))
	defer server.Close()

	log.SetOutput(ioutil.Discard)
	resp, err := http.Get(fmt.Sprintf("%s/panic", server.URL))
	log.SetOutput(os.Stderr)

	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Errorf("Expected server to respond with 500")
	}
}

func panickingHandler(w http.ResponseWriter, r *http.Request) {
	panic("Something went wrong")
}

// Helper function to mock a request to the server via https.
// Returns http.Response resulting from specified handler.
func testRequest(method string, url string, handler func(http.ResponseWriter, *http.Request)) *http.Response {
	req := httptest.NewRequest(method, fmt.Sprintf("http://localhost:8080/%s", url), nil)
	w := httptest.NewRecorder()
	handler(w, req)
	return w.Result()
}

func TestGetDomainHidesEmail(t *testing.T) {
	testRequest("POST", "/api/queue?domain=eff.org&email=testing@fake-email.org", api.Queue)
	resp := testRequest("GET", "/api/queue?domain=eff.org", api.Queue)
	// Check to see domain JSON hides email
	domainBody, _ := ioutil.ReadAll(resp.Body)
	if bytes.Contains(domainBody, []byte("testing@fake-email.org")) {
		t.Errorf("Domain object includes e-mail address!")
	}
}

// Tests basic queuing workflow.
// Requests domain to be queued, and validates corresponding e-mail token.
// Domain status should then be updated to "queued".
func TestBasicQueueWorkflow(t *testing.T) {
	// 1. Request to be queued
	resp := testRequest("POST", "/api/queue?domain=eff.org&email=testing@fake-email.org", api.Queue)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST to api/queue?domain=eff.org failed with error %d", resp.StatusCode)
		return
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// 1-T. Check that response body contains a token we can validate
	tokenBody, _ := ioutil.ReadAll(resp.Body)
	var tokenObj map[string]interface{}
	err := json.Unmarshal(tokenBody, &tokenObj)
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(tokenBody))
		return
	}
	token, ok := tokenObj["token"]
	if !ok {
		t.Errorf("Expected Token to be returned in JSON")
		return
	}
	if tokenObj["domain"] != "eff.org" {
		t.Errorf("Token JSON expected to have Domain: eff.org, not %s\n", tokenObj["domain"])
	}

	// 2. Request queue status
	resp = testRequest("GET", "/api/queue?domain=eff.org", api.Queue)
	// 2-T. Check to see domain status was initialized to 'unvalidated'
	domainBody, _ := ioutil.ReadAll(resp.Body)
	var domainObj map[string]interface{}
	err = json.Unmarshal(domainBody, &domainObj)
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(domainBody))
		return
	}
	if domainObj["state"] != "unvalidated" {
		t.Errorf("Initial state for domains should be 'unvalidated'")
		return
	}

	// 3. Validate domain token
	resp = testRequest("POST", fmt.Sprintf("/api/validate?token=%s", token), api.Validate)
	// 3-T. Ensure response body contains domain name
	domainBody, _ = ioutil.ReadAll(resp.Body)
	var domain string
	err = json.Unmarshal(domainBody, &domain)
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(domainBody))
		return
	}
	if domain != "eff.org" {
		t.Errorf("Token was not validated for eff.org")
		return
	}

	// 3-T2. Ensure double-validation does not work.
	resp = testRequest("POST", fmt.Sprintf("/api/validate?token=%s", token), api.Validate)
	if resp.StatusCode != 400 {
		t.Errorf("Validation token shouldn't be able to be used twice!")
	}

	// 4. Request queue status again
	resp = testRequest("GET", "/api/queue?domain=eff.org", api.Queue)
	// 4-T. Check to see domain status was updated to "queued" after valid token redemption
	domainBody, _ = ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(domainBody, &domainObj)
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(domainBody))
		return
	}
	if domainObj["state"] != "queued" {
		t.Errorf("Token validation should have automatically queued eff.org")
		return
	}
}

// Tests basic scanning workflow.
// Requests a scan for a particular domain, and
// makes sure that the scan is persisted correctly in DB across requests.
func TestBasicScan(t *testing.T) {
	api.Database.ClearTables()
	// Request a scan!
	resp := testRequest("POST", "/api/scan?domain=eff.org", api.Scan)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST to api/scan?domain=eff.org failed with error %d", resp.StatusCode)
		return
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// Checking response JSON returns successful scan
	scanBody, _ := ioutil.ReadAll(resp.Body)
	var jsonObj map[string]interface{}
	err := json.Unmarshal(scanBody, &jsonObj)
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(scanBody))
	}
	if domain, ok := jsonObj["Domain"]; !ok {
		t.Errorf("Scan JSON should contain Domain field")
	} else {
		if domain != "eff.org" {
			t.Errorf("Scan JSON expected to have Domain: eff.org, not %s\n", domain)
		}
	}

	// Check to see that scan results persisted.
	resp = testRequest("GET", "api/scan?domain=eff.org", api.Scan)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET api/scan?domain=eff.org failed with error %d", resp.StatusCode)
		return
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// Checking response JSON returns scan associated with domain
	body, _ := ioutil.ReadAll(resp.Body)
	var jsonObj2 map[string]string
	err = json.Unmarshal(body, &jsonObj2)
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(body))
	}
	if domain, ok := jsonObj2["domain"]; !ok {
		t.Errorf("Scan JSON should contain Domain field")
	} else {
		if domain != "eff.org" {
			t.Errorf("Scan JSON expected to have Domain: eff.org, not %s\n", domain)
		}
	}
	if scandata, ok := jsonObj2["scandata"]; !ok {
		t.Errorf("Scan JSON should contain Domain field")
	} else {
		if strings.Compare(scandata, strings.TrimSpace(string(scanBody))) != 0 {
			t.Errorf("Scan JSON mismatch:\n%s\n%s\n", scandata, string(scanBody))
		}
	}
}
