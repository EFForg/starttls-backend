package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
)

func TestGetStats(t *testing.T) {
	now := time.Now()
	s := models.Scan{
		Domain:    "example.com",
		Data:      checker.NewSampleDomainResult("example.com"),
		Timestamp: now,
	}
	api.Database.PutScan(s)

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
	date := now.UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
	expectedX := fmt.Sprintf("\"x\": \"%v\"", date)
	if !strings.Contains(string(body), expectedX) {
		t.Errorf("Expected %s to contain %s", string(body), expectedX)
	}
	expectedY := fmt.Sprintf("\"y\": 100")
	if !strings.Contains(string(body), expectedY) {
		t.Errorf("Expected %s to contain %s", string(body), expectedY)
	}
}
