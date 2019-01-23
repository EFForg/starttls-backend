package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/EFForg/starttls-backend/models"
)

func TestScanHTML(t *testing.T) {
	defer teardown()

	// Request a scan!
	data := url.Values{}
	data.Set("domain", "eff.org")
	body, status := testHTMLPost("/api/scan", data, t)
	if status != http.StatusOK {
		t.Errorf("HTML POST to api/scan failed with error %d", status)
	}
	if !strings.Contains(string(body), "eff.org") {
		t.Errorf("Response should contain scan domain, got %s", string(body))
	}
}

// Tests basic scanning workflow.
// Requests a scan for a particular domain, and
// makes sure that the scan is persisted correctly in DB across requests.
func TestBasicScan(t *testing.T) {
	defer teardown()

	// Request a scan!
	data := url.Values{}
	data.Set("domain", "eff.org")
	resp, _ := http.PostForm(server.URL+"/api/scan", data)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/scan failed with error %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// Checking response JSON returns successful scan
	scanBody, _ := ioutil.ReadAll(resp.Body)
	scan := models.Scan{}
	err := json.Unmarshal(scanBody, &APIResponse{Response: &scan})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n%v\n", string(scanBody), err)
	}
	if scan.Domain != "eff.org" {
		t.Errorf("Scan JSON expected to have Domain: eff.org, not %s\n", scan.Domain)
	}

	// Check to see that scan results persisted.
	resp, _ = http.Get(server.URL + "/api/scan?domain=eff.org")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET api/scan?domain=eff.org failed with error %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	// Checking response JSON returns scan associated with domain
	scanBody, _ = ioutil.ReadAll(resp.Body)
	scan2 := models.Scan{}
	err = json.Unmarshal(scanBody, &APIResponse{Response: &scan2})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n", string(scanBody))
	}
	if scan2.Domain != "eff.org" {
		t.Errorf("Scan JSON expected to have Domain: eff.org, not %s\n", scan2.Domain)
	}
	if strings.Compare(scan.Data.Domain, scan2.Data.Domain) != 0 {
		t.Errorf("Scan JSON mismatch:\n%v\n%v\n", scan.Data.Domain, scan2.Data.Domain)
	}
}

func TestDontScanList(t *testing.T) {
	defer teardown()

	data := url.Values{}
	data.Set("domain", "dontscan.com")
	resp, _ := http.PostForm(server.URL+"/api/scan", data)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("GET api/scan?domain=dontscan.com should have failed with %d", resp.StatusCode)
	}
}

func TestScanCached(t *testing.T) {
	defer teardown()

	data := url.Values{}
	data.Set("domain", "eff.org")
	http.PostForm(server.URL+"/api/scan", data)
	original, _ := api.CheckDomain(*api, "eff.org")
	// Perform scan again, with different expected result.
	api.CheckDomain = mockCheckPerform("somethingelse")
	resp, _ := http.PostForm(server.URL+"/api/scan", data)
	scanBody, _ := ioutil.ReadAll(resp.Body)
	scan := models.Scan{}
	// Since scan occurred recently, we should have returned the cached OG response.
	err := json.Unmarshal(scanBody, &APIResponse{Response: &scan})
	if err != nil {
		t.Errorf("Returned invalid JSON object:%v\n%v\n", string(scanBody), err)
	}
	if scan.Data.Message != original.Message {
		t.Fatalf("Scan expected to have been cached, not reperformed\n")
	}
}
