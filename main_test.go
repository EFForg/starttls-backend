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
	"time"

	"github.com/EFForg/starttls-check/checker"
	"github.com/EFForg/starttls-scanner/db"
	"github.com/EFForg/starttls-scanner/policy"
)

// Workflow tests against REST API.

var api *API

func mockCheckPerform(message string) func(API, string) (checker.DomainResult, error) {
	return func(api API, domain string) (checker.DomainResult, error) {
		return checker.DomainResult{Domain: domain, Message: message}, nil
	}
}

// Mock PolicyList
type mockList struct {
	domains map[string]bool
}

func (l mockList) Get(domain string) (policy.TLSPolicy, error) {
	if _, ok := l.domains[domain]; ok {
		return policy.TLSPolicy{Mode: "enforce", MXs: []string{"mx.fake.com"}}, nil
	}
	return policy.TLSPolicy{}, fmt.Errorf("no such domain on this list")
}

// Mock emailer
type mockEmailer struct{}

func (e mockEmailer) SendValidation(domainInfo *db.DomainData, token string) error { return nil }

// Load env. vars, initialize DB hook, and tests API
func TestMain(m *testing.M) {
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	// Note: we can use either MemDatabase or SQLDatabase here, should not make a difference.
	// db, err := db.InitSQLDatabase(cfg)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	fakeList := map[string]bool{
		"eff.org": true,
	}
	api = &API{
		Database:    db.InitMemDatabase(cfg),
		CheckDomain: mockCheckPerform("testequal"),
		List:        mockList{domains: fakeList},
		Emailer:     mockEmailer{},
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

	resp, err := http.Get(fmt.Sprintf("%s/panic", server.URL))

	if err != nil {
		t.Errorf("Request to panic endpoint failed: %s\n", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected server to respond with 500, got %d", resp.StatusCode)
	}
}

func panickingHandler(w http.ResponseWriter, r *http.Request) {
	panic(fmt.Errorf("oh no"))
}

func TestRateLimitByIP(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(registerHandlers(api, mux))
	defer server.Close()

	for i := 0; i < 10; i++ {
		http.Get(fmt.Sprintf("%s/", server.URL))
	}
	resp, err := http.Get(fmt.Sprintf("%s/", server.URL))

	if err != nil {
		t.Errorf("Rate limit request failed: %s\n", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected server to respond with 429, got %d", resp.StatusCode)
	}
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

func validQueueData(scan bool) url.Values {
	data := url.Values{}
	data.Set("domain", "eff.org")
	if scan {
		testRequest("POST", "/api/scan", data, api.Scan)
	}
	data.Set("email", "testing@fake-email.org")
	data.Add("hostnames", ".eff.org")
	data.Add("hostnames", "mx.eff.org")
	return data
}

func TestGetDomainHidesEmail(t *testing.T) {
	requestData := validQueueData(true)
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
	requestData := validQueueData(true)
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
	queueDomainPostData := validQueueData(true)
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

func TestQueueWithoutScan(t *testing.T) {
	api.Database.ClearTables()
	requestData := validQueueData(false)
	resp := testRequest("POST", "/api/queue", requestData, api.Queue)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST to api/queue should have failed with error %d", resp.StatusCode)
	}
}

func TestQueueInvalidDomain(t *testing.T) {
	requestData := validQueueData(true)
	requestData.Add("hostnames", "banana")
	resp := testRequest("POST", "/api/queue", requestData, api.Queue)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected POST to api/queue to fail.")
	}
}

func TestQueueTwice(t *testing.T) {
	// 1. Request to be queued
	requestData := validQueueData(true)
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

func TestPolicyCheck(t *testing.T) {
	result := api.policyCheck("eff.org")
	if result.Status != checker.Success {
		t.Errorf("Check should have succeeded.")
	}
	result = api.policyCheck("failmail.com")
	if result.Status != checker.Failure {
		t.Errorf("Check should have failed.")
	}
}

func TestPolicyCheckWithQueuedDomain(t *testing.T) {
	api.Database.ClearTables()
	domainData := db.DomainData{
		Name:  "example.com",
		Email: "postmaster@example.com",
		State: db.StateUnvalidated,
	}
	api.Database.PutDomain(domainData)
	result := api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
	}
	domainData.State = db.StateQueued
	api.Database.PutDomain(domainData)
	result = api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
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
	if strings.Compare(scanData.Data.Domain, scanData2.Data.Domain) != 0 {
		t.Errorf("Scan JSON mismatch:\n%v\n%v\n", scanData.Data.Domain, scanData2.Data.Domain)
	}
}

func TestDontScanList(t *testing.T) {
	api.DontScan = map[string]bool{"dontscan.com": true}
	data := url.Values{}
	data.Set("domain", "dontscan.com")
	resp := testRequest("POST", "/api/scan", data, api.Scan)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("GET api/scan?domain=dontscan.com should have failed with %d", resp.StatusCode)
	}
}

func TestScanCached(t *testing.T) {
	api.Database.ClearTables()
	data := url.Values{}
	data.Set("domain", "eff.org")
	testRequest("POST", "/api/scan", data, api.Scan)
	original, _ := api.CheckDomain(*api, "eff.org")
	// Perform scan again, with different expected result.
	api.CheckDomain = mockCheckPerform("somethingelse")
	resp := testRequest("POST", "/api/scan", data, api.Scan)
	scanBody, _ := ioutil.ReadAll(resp.Body)
	scanData := db.ScanData{}
	// Since scan occurred recently, we should have returned the cached OG response.
	err := json.Unmarshal(scanBody, &APIResponse{Response: &scanData})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n%v\n", string(scanBody), err)
	}
	if scanData.Data.Message != original.Message {
		t.Fatalf("Scan expected to have been cached, not reperformed\n")
	}
}

func TestValidationEmailText(t *testing.T) {
	content := validationEmailText("example.com", []string{"mx.example.com, .mx.example.com"}, "abcd", time.Now(),
		"https://fake.starttls-everywhere.website")
	if !strings.Contains(content, "https://fake.starttls-everywhere.website/validate/abcd") {
		t.Errorf("E-mail formatted incorrectly.")
	}
}
