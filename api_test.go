package main

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
)

func TestPolicyCheck(t *testing.T) {
	defer teardown()

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
	defer teardown()

	domain := models.Domain{
		Name:  "example.com",
		Email: "postmaster@example.com",
		State: models.StateUnvalidated,
	}
	api.Database.PutDomain(domain)
	result := api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
	}
	domain.State = models.StateQueued
	api.Database.PutDomain(domain)
	result = api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
	}
}

func testHTMLPost(path string, data url.Values, t *testing.T) ([]byte, int) {
	req, err := http.NewRequest("POST", server.URL+path, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "text/html")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if !strings.Contains(strings.ToLower(string(body)), "</html") {
		t.Errorf("Response should be HTML, got %s", string(body))
	}
	return body, resp.StatusCode
}
