package api

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

func TestGetStats(t *testing.T) {
	err := api.Database.PutAggregatedScan(checker.AggregatedScan{
		Time:          time.Now(),
		Source:        checker.LocalSource,
		Attempted:     10,
		WithMXs:       8,
		MTASTSTesting: 3,
		MTASTSEnforce: 2,
	})

	err = api.Database.PutAggregatedScan(checker.AggregatedScan{
		Time:          time.Now(),
		Source:        checker.TopDomainsSource,
		Attempted:     10,
		WithMXs:       8,
		MTASTSTesting: 3,
		MTASTSEnforce: 2,
	})

	resp, err := http.Get(server.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/stats failed with error %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expecting JSON content-type!")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// Local source returns a percent
	expectedY := fmt.Sprintf("\"y\": 62.5")
	if !strings.Contains(string(body), expectedY) {
		t.Errorf("Expected %s to contain %s", string(body), expectedY)
	}
	// Top domains source returns a raw count
	expectedY = fmt.Sprintf("\"y\": 5")
	if !strings.Contains(string(body), expectedY) {
		t.Errorf("Expected %s to contain %s", string(body), expectedY)
	}
}
