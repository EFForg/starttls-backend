package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/EFForg/starttls-scanner/db"
)

// Workflow tests against REST API.
// TODO: Mock starttls-scanner/check so we don't actually make check requests

var api *API

func mockCheckPerform(domain string) (string, error) {
	return fmt.Sprintf("{\n\"domain\": \"%s\"\n}", domain), nil
}

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
		Database:    db.InitMemDatabase(cfg),
		CheckDomain: mockCheckPerform,
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
func testRequest(method string, path string, data url.Values, handler apiHandler) *http.Response {
	req := httptest.NewRequest(method, fmt.Sprintf("http://localhost:8080/%s", path), strings.NewReader(data.Encode()))
	if data != nil {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	apiWrapper(handler)(w, req)
	return w.Result()
}

func TestGetDomainHidesEmail(t *testing.T) {
	testRequest("POST", "/api/queue?domain=eff.org&email=testing@fake-email.org", nil, api.Queue)
	resp := testRequest("GET", "/api/queue?domain=eff.org", nil, api.Queue)
	// Check to see domain JSON hides email
	domainBody, _ := ioutil.ReadAll(resp.Body)
	if bytes.Contains(domainBody, []byte("testing@fake-email.org")) {
		t.Errorf("Domain object includes e-mail address!")
	}
}

func TestQueueDomainHidesToken(t *testing.T) {
	data := url.Values{}
	data.Set("domain", "eff.org")
	data.Set("email", "testing@fake-email.org")
	data.Set("hostname_0", ".eff.org")
	resp := testRequest("POST", "/api/queue", data, api.Queue)

	token, err := api.Database.GetTokenByDomain("eff.org")
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := ioutil.ReadAll(resp.Body)
	if bytes.Contains(responseBody, []byte(token)) {
		t.Errorf("Queueing domain leaks validation token")
	}
}

// Tests basic queuing workflow.
// Requests domain to be queued, and validates corresponding e-mail token.
// Domain status should then be updated to "queued".
func TestBasicQueueWorkflow(t *testing.T) {
	// 1. Request to be queued
	data := url.Values{}
	data.Set("domain", "eff.org")
	data.Set("email", "testing@fake-email.org")
	data.Set("hostname_0", ".eff.org")
	data.Set("hostname_1", "mx.eff.org")
	resp := testRequest("POST", "/api/queue", data, api.Queue)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST to api/queue failed with error %d", resp.StatusCode)
		return
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// 2. Request queue status
	resp = testRequest("GET", "/api/queue?domain=eff.org", nil, api.Queue)
	// 2-T. Check to see domain status was initialized to 'unvalidated'
	domainBody, _ := ioutil.ReadAll(resp.Body)
	domainData := db.DomainData{}
	err := json.Unmarshal(domainBody, &APIResponse{Response: &domainData})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(domainBody))
		return
	}
	if domainData.State != "unvalidated" {
		t.Errorf("Initial state for domains should be 'unvalidated'")
		return
	}
	if len(domainData.MXs) != 2 {
		t.Errorf("Domain should have loaded two hostnames into policy")
		return
	}

	// 3. Validate domain token
	token, err := api.Database.GetTokenByDomain("eff.org")
	if err != nil {
		t.Errorf("Token for eff.org not found in database")
		return
	}
	data = url.Values{}
	data.Set("token", token)
	resp = testRequest("POST", "/api/validate", data, api.Validate)
	// 3-T. Ensure response body contains domain name
	domainBody, _ = ioutil.ReadAll(resp.Body)
	var responseObj map[string]interface{}
	err = json.Unmarshal(domainBody, &responseObj)
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(domainBody))
		return
	}
	if responseObj["response"] != "eff.org" {
		t.Errorf("Token was not validated for eff.org")
		return
	}

	// 3-T2. Ensure double-validation does not work.
	resp = testRequest("POST", "/api/validate", data, api.Validate)
	if resp.StatusCode != 400 {
		t.Errorf("Validation token shouldn't be able to be used twice!")
	}

	// 4. Request queue status again
	resp = testRequest("GET", "/api/queue?domain=eff.org", nil, api.Queue)
	// 4-T. Check to see domain status was updated to "queued" after valid token redemption
	domainBody, _ = ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(domainBody, &APIResponse{Response: &domainData})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(domainBody))
		return
	}
	if domainData.State != "queued" {
		t.Errorf("Token validation should have automatically queued eff.org")
		return
	}
}

func TestQueueWithoutHostnames(t *testing.T) {
	data := url.Values{}
	data.Set("domain", "eff.org")
	data.Set("email", "testing@fake-email.org")
	resp := testRequest("POST", "/api/queue", data, api.Queue)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST to api/queue should have failed with error %d", http.StatusBadRequest)
		return
	}
}

func TestQueueTwice(t *testing.T) {
	// 1. Request to be queued
	data := url.Values{}
	data.Set("domain", "eff.org")
	data.Set("email", "testing@fake-email.org")
	data.Set("hostname_0", ".eff.org")
	data.Set("hostname_1", "mx.eff.org")
	resp := testRequest("POST", "/api/queue", data, api.Queue)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST to api/queue failed with error %d", resp.StatusCode)
		return
	}

	// 2. Get token from DB
	token, err := api.Database.GetTokenByDomain("eff.org")
	if err != nil {
		t.Errorf("Token for eff.org not found in database")
		return
	}

	// 3. Request to be queued again.
	resp = testRequest("POST", "/api/queue", data, api.Queue)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST to api/queue failed with error %d", resp.StatusCode)
		return
	}

	// 4. Old token shouldn't work.
	data = url.Values{}
	data.Set("token", token)
	resp = testRequest("POST", "/api/validate", data, api.Validate)
	if resp.StatusCode != 400 {
		t.Errorf("Old validation token shouldn't work.")
	}
}

// Tests basic scanning workflow.
// Requests a scan for a particular domain, and
// makes sure that the scan is persisted correctly in DB across requests.
func TestBasicScan(t *testing.T) {
	api.Database.ClearTables()
	// Request a scan!
	data := url.Values{}
	data.Set("domain", "eff.org")
	resp := testRequest("POST", "/api/scan", data, api.Scan)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST to api/scan failed with error %d", resp.StatusCode)
		return
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// Checking response JSON returns successful scan
	scanBody, _ := ioutil.ReadAll(resp.Body)
	scanData := db.ScanData{}
	err := json.Unmarshal(scanBody, &APIResponse{Response: &scanData})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n%v\n", string(scanBody), err)
	}
	if scanData.Domain != "eff.org" {
		t.Errorf("Scan JSON expected to have Domain: eff.org, not %s\n", scanData.Domain)
	}

	// Check to see that scan results persisted.
	resp = testRequest("GET", "api/scan?domain=eff.org", nil, api.Scan)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET api/scan?domain=eff.org failed with error %d", resp.StatusCode)
		return
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// Checking response JSON returns scan associated with domain
	scanBody, _ = ioutil.ReadAll(resp.Body)
	scanData2 := db.ScanData{}
	err = json.Unmarshal(scanBody, &APIResponse{Response: &scanData2})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(scanBody))
	}
	if scanData2.Domain != "eff.org" {
		t.Errorf("Scan JSON expected to have Domain: eff.org, not %s\n", scanData2.Domain)
	}
	if strings.Compare(scanData2.Data, scanData.Data) != 0 {
		t.Errorf("Scan JSON mismatch:\n%v\n%v\n", scanData2.Data, scanData.Data)
	}
}
