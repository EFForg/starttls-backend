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
		Name:  "example.com",
		Email: "postmaster@example.com",
		MXs:   []string{"a.b.c"}})
	api.Database.PutDomain(db.DomainData{
		Name: "example.com", State: db.StateQueued})
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
