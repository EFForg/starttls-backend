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
		t.Fatalf("Should not have errored on valid string: %v", err)
	}
	if portString != ":8000" {
		t.Fatalf("Expected portstring be :8000 instead of %s", portString)
	}
	portString, err = validPort("80a")
	if err == nil {
		t.Fatalf("Expected error on invalid port")
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

func validQueueData() url.Values {
	data := url.Values{}
	data.Set("domain", "eff.org")
	data.Set("email", "testing@fake-email.org")
	data.Set("hostname_0", ".eff.org")
	data.Set("hostname_1", "mx.eff.org")
	return data
}

func TestGetDomainHidesEmail(t *testing.T) {
	requestData := validQueueData()
	testRequest("POST", "/api/queue", requestData, api.Queue)

	path := fmt.Sprintf("/api/queue?domain=%s", requestData.Get("domain"))
	resp := testRequest("GET", path, nil, api.Queue)

	// Check to see domain JSON hides email
	domainBody, _ := ioutil.ReadAll(resp.Body)
	if bytes.Contains(domainBody, []byte(requestData.Get("email"))) {
		t.Errorf("Domain object includes e-mail address!")
	}
}

func TestQueueDomainHidesToken(t *testing.T) {
	requestData := validQueueData()
	resp := testRequest("POST", "/api/queue", requestData, api.Queue)

	token, err := api.Database.GetTokenByDomain(requestData.Get("domain"))
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
	queueDomainPostData := validQueueData()
	resp := testRequest("POST", "/api/queue", queueDomainPostData, api.Queue)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/queue failed with error %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// 2. Request queue status
	queueDomainGetPath := fmt.Sprintf("/api/queue?domain=%s", queueDomainPostData.Get("domain"))
	resp = testRequest("GET", queueDomainGetPath, nil, api.Queue)
	// 2-T. Check to see domain status was initialized to 'unvalidated'
	domainBody, _ := ioutil.ReadAll(resp.Body)
	domainData := db.DomainData{}
	err := json.Unmarshal(domainBody, &APIResponse{Response: &domainData})
	if err != nil {
		t.Fatalf("Returned invalid JSON object:%v\n", string(domainBody))
	}
	if domainData.State != "unvalidated" {
		t.Fatalf("Initial state for domains should be 'unvalidated'")
	}
	if len(domainData.MXs) != 2 {
		t.Fatalf("Domain should have loaded two hostnames into policy")
	}

	// 3. Validate domain token
	token, err := api.Database.GetTokenByDomain(queueDomainPostData.Get("domain"))
	if err != nil {
		t.Fatalf("Token not found in database")
	}
	tokenRequestData := url.Values{}
	tokenRequestData.Set("token", token)
	resp = testRequest("POST", "/api/validate", tokenRequestData, api.Validate)
	// 3-T. Ensure response body contains domain name
	domainBody, _ = ioutil.ReadAll(resp.Body)
	var responseObj map[string]interface{}
	err = json.Unmarshal(domainBody, &responseObj)
	if err != nil {
		t.Fatalf("Returned invalid JSON object:%v\n", string(domainBody))
	}
	if responseObj["response"] != queueDomainPostData.Get("domain") {
		t.Fatalf("Token was not validated for %s", queueDomainPostData.Get("domain"))
	}

	// 3-T2. Ensure double-validation does not work.
	resp = testRequest("POST", "/api/validate", tokenRequestData, api.Validate)
	if resp.StatusCode != 400 {
		t.Errorf("Validation token shouldn't be able to be used twice!")
	}

	// 4. Request queue status again
	resp = testRequest("GET", queueDomainGetPath, nil, api.Queue)
	// 4-T. Check to see domain status was updated to "queued" after valid token redemption
	domainBody, _ = ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(domainBody, &APIResponse{Response: &domainData})
	if err != nil {
		t.Fatalf("Returned invalid JSON object:%v\n", string(domainBody))
	}
	if domainData.State != "queued" {
		t.Fatalf("Token validation should have automatically queued domain")
	}
}

func TestQueueWithoutHostnames(t *testing.T) {
	data := url.Values{}
	data.Set("domain", "eff.org")
	data.Set("email", "testing@fake-email.org")
	resp := testRequest("POST", "/api/queue", data, api.Queue)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST to api/queue should have failed with error %d", http.StatusBadRequest)
	}
}

func TestQueueTwice(t *testing.T) {
	// 1. Request to be queued
	requestData := validQueueData()
	resp := testRequest("POST", "/api/queue", requestData, api.Queue)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/queue failed with error %d", resp.StatusCode)
	}

	// 2. Get token from DB
	token, err := api.Database.GetTokenByDomain("eff.org")
	if err != nil {
		t.Fatalf("Token for eff.org not found in database")
	}

	// 3. Request to be queued again.
	resp = testRequest("POST", "/api/queue", requestData, api.Queue)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/queue failed with error %d", resp.StatusCode)
	}

	// 4. Old token shouldn't work.
	requestData = url.Values{}
	requestData.Set("token", token)
	resp = testRequest("POST", "/api/validate", requestData, api.Validate)
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
		t.Fatalf("POST to api/scan failed with error %d", resp.StatusCode)
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
		t.Fatalf("GET api/scan?domain=eff.org failed with error %d", resp.StatusCode)
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
