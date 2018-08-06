package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/EFForg/starttls-scanner/db"
)

func validQueueData(scan bool) url.Values {
	data := url.Values{}
	data.Set("domain", "eff.org")
	if scan {
		http.PostForm(server.URL+"/api/scan", data)
	}
	data.Set("email", "testing@fake-email.org")
	data.Add("hostnames", ".eff.org")
	data.Add("hostnames", "mx.eff.org")
	return data
}

func TestGetDomainHidesEmail(t *testing.T) {
	defer teardown()

	requestData := validQueueData(true)
	http.PostForm(server.URL+"/api/queue", requestData)

	resp, _ := http.Get(server.URL + "/api/queue?domain=" + requestData.Get("domain"))

	// Check to see domain JSON hides email
	domainBody, _ := ioutil.ReadAll(resp.Body)
	if bytes.Contains(domainBody, []byte(requestData.Get("email"))) {
		t.Errorf("Domain object includes e-mail address!")
	}
}

func TestQueueDomainHidesToken(t *testing.T) {
	defer teardown()

	requestData := validQueueData(true)
	resp, _ := http.PostForm(server.URL+"/api/queue", requestData)

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
	defer teardown()

	// 1. Request to be queued
	queueDomainPostData := validQueueData(true)
	resp, _ := http.PostForm(server.URL+"/api/queue", queueDomainPostData)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/queue failed with error %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// 2. Request queue status
	queueDomainGetPath := server.URL + "/api/queue?domain=" + queueDomainPostData.Get("domain")
	resp, _ = http.Get(queueDomainGetPath)

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
	resp, err = http.PostForm(server.URL+"/api/validate", tokenRequestData)
	if err != nil {
		t.Fatal(err)
	}

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
	resp, _ = http.PostForm(server.URL+"/api/validate", tokenRequestData)
	if resp.StatusCode != 400 {
		t.Errorf("Validation token shouldn't be able to be used twice!")
	}

	// 4. Request queue status again
	resp, _ = http.Get(queueDomainGetPath)

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
	defer teardown()

	data := url.Values{}
	data.Set("domain", "eff.org")
	data.Set("email", "testing@fake-email.org")
	resp, _ := http.PostForm(server.URL+"/api/queue", data)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST to api/queue should have failed with error %d", http.StatusBadRequest)
	}
}

func TestQueueWithoutScan(t *testing.T) {
	defer teardown()

	requestData := validQueueData(false)
	resp, _ := http.PostForm(server.URL+"/api/queue", requestData)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST to api/queue should have failed with error %d", resp.StatusCode)
	}
}

func TestQueueInvalidDomain(t *testing.T) {
	defer teardown()

	requestData := validQueueData(true)
	requestData.Add("hostnames", "banana")
	resp, _ := http.PostForm(server.URL+"/api/queue", requestData)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected POST to api/queue to fail.")
	}
}

func TestQueueEmptyHostname(t *testing.T) {
	defer teardown()

	// The HTML form will submit hostnames fields left blank as empty strings.
	requestData := validQueueData(true)
	requestData.Add("hostnames", "")
	resp, _ := http.PostForm(server.URL+"/api/queue", requestData)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected empty hostname submissions to be filtered out.")
	}
}

func TestQueueTwice(t *testing.T) {
	defer teardown()

	// 1. Request to be queued
	requestData := validQueueData(true)
	resp, _ := http.PostForm(server.URL+"/api/queue", requestData)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/queue failed with error %d", resp.StatusCode)
	}

	// 2. Get token from DB
	token, err := api.Database.GetTokenByDomain("eff.org")
	if err != nil {
		t.Fatalf("Token for eff.org not found in database")
	}

	// 3. Request to be queued again.
	resp, _ = http.PostForm(server.URL+"/api/queue", requestData)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/queue failed with error %d", resp.StatusCode)
	}

	// 4. Old token shouldn't work.
	requestData = url.Values{}
	requestData.Set("token", token)
	resp, _ = http.PostForm(server.URL+"/api/validate", requestData)
	if resp.StatusCode != 400 {
		t.Errorf("Old validation token shouldn't work.")
	}
}
