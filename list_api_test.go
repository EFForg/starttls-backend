package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/policy"
)

func TestGetListBasic(t *testing.T) {
	defer teardown()
	resp, _ := http.Get(server.URL + "/auth/list")
	body, _ := ioutil.ReadAll(resp.Body)
	var list policy.List
	json.Unmarshal(body, &APIResponse{Response: &list})
	if _, ok := list.Policies["eff.org"]; !ok {
		t.Errorf("Expected eff.org to be on mock policy list")
	}
}

func queueDomain(domain string) {
	api.Database.PutDomain(db.DomainData{
		Name:  domain,
		Email: "postmaster@example.com",
		MXs:   []string{"a.b.c"}})
	api.Database.PutDomain(db.DomainData{
		Name: domain, State: db.StateQueued})
}

func expectDomainState(t *testing.T, domain string, expectedState db.DomainState) {
	resp, _ := http.Get(server.URL + "/api/queue?domain=" + domain)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected domain get to succeed")
	}
	domainBody, _ := ioutil.ReadAll(resp.Body)
	domainData := db.DomainData{}
	err := json.Unmarshal(domainBody, &APIResponse{Response: &domainData})
	if err != nil {
		t.Fatalf("returned invalid JSON object:%v\n", string(domainBody))
	}
	if domainData.Name != domain {
		t.Errorf("should have retrieved info for %s,  not %s\n", domain, domainData.Name)
	}
	if domainData.State != expectedState {
		t.Errorf("expected state to be StateAdded, got %v\n", domainData.State)
	}
}

func TestGetListWithQueuedDomainsAdded(t *testing.T) {
	defer teardown()
	queueDomain("example.com")
	resp, _ := http.Get(server.URL + "/auth/list?queued_weeks=0")
	body, _ := ioutil.ReadAll(resp.Body)
	var list policy.List
	json.Unmarshal(body, &APIResponse{Response: &list})
	if _, ok := list.Policies["example.com"]; !ok {
		t.Errorf("Expected example.com to be on mock policy list")
	}
}

func TestGetListNewQueuedDomainsNotAdded(t *testing.T) {
	defer teardown()
	queueDomain("example.com")
	resp, _ := http.Get(server.URL + "/auth/list?queued_weeks=1")
	body, _ := ioutil.ReadAll(resp.Body)
	var list policy.List
	json.Unmarshal(body, &APIResponse{Response: &list})
	if _, ok := list.Policies["example.com"]; ok {
		t.Errorf("Did not expect example.com to be on mock policy list")
	}
}

func TestGetListExpiryTime(t *testing.T) {
	defer teardown()
	lowerBound := time.Now().Add(4 * 7 * 24 * time.Hour)
	resp, _ := http.Get(server.URL + "/auth/list?expire_weeks=4")
	upperBound := time.Now().Add(4 * 7 * 24 * time.Hour)
	body, _ := ioutil.ReadAll(resp.Body)
	var list policy.List
	json.Unmarshal(body, &APIResponse{Response: &list})
	if list.Expires.Before(lowerBound) {
		t.Errorf("list expires too early")
	}
	if list.Expires.After(upperBound) {
		t.Errorf("list expires too late")
	}
}

func TestFailDomainFailsIfDomainDoesntExist(t *testing.T) {
	defer teardown()
	resp, _ := http.PostForm(server.URL+"/auth/fail?domain=example.com", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 4** bad request from requesting to fail not queued domain: %v", resp)
	}
}

func TestFailDomain(t *testing.T) {
	defer teardown()
	queueDomain("example.com")
	resp, _ := http.PostForm(server.URL+"/auth/fail?domain=example.com", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected domain update to succeed")
	}
	expectDomainState(t, "example.com", db.StateFailed)
}

func TestFailDomainNoGets(t *testing.T) {
	defer teardown()
	resp, _ := http.Get(server.URL + "/auth/fail?domain=example.com")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 4** Method Not Allowed since /auth/fail only accepts POSTs")
	}
}

func TestSyncListNoGets(t *testing.T) {
	defer teardown()
	resp, _ := http.Get(server.URL + "/auth/promote")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 4** Method Not Allowed since /auth/promote only accepts POSTs")
	}
}

func TestSyncList(t *testing.T) {
	queueDomain("example.com")
	queueDomain("eff.org")
	resp, _ := http.PostForm(server.URL+"/auth/promote", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected promote to succeed")
	}
	expectDomainState(t, "eff.org", db.StateAdded)
	expectDomainState(t, "example.com", db.StateQueued)
}
