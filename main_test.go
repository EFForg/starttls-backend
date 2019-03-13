package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/policy"
	"github.com/joho/godotenv"
)

// Setup, teardown, and shared mocks and helpers for integration tests.

var api *API
var server *httptest.Server

func mockCheckPerform(message string) func(API, string) (checker.DomainResult, error) {
	return func(api API, domain string) (checker.DomainResult, error) {
		return checker.NewSampleDomainResult(domain), nil
	}
}

// Mock PolicyList
type mockList struct {
	domains map[string]bool
}

func (l mockList) Raw() policy.List {
	list := policy.List{
		Timestamp:     time.Now(),
		Expires:       time.Now().Add(time.Minute),
		Version:       "",
		Author:        "",
		Pinsets:       make(map[string]policy.Pinset),
		PolicyAliases: make(map[string]policy.TLSPolicy),
		Policies:      make(map[string]policy.TLSPolicy),
	}
	for domain := range l.domains {
		list.Policies[domain] =
			policy.TLSPolicy{Mode: "enforce", MXs: []string{"mx.fake.com"}}
	}
	return list
}

func (l mockList) HasDomain(domain string) bool {
	_, ok := l.domains[domain]
	return ok
}

// Mock emailer
type mockEmailer struct{}

func (e mockEmailer) SendValidation(domain *models.Domain, token string) error { return nil }

// Load env. vars, initialize DB hook, and tests API
func TestMain(m *testing.M) {
	godotenv.Overload(".env.test")
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	sqldb, err := db.InitSQLDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	fakeList := map[string]bool{
		"eff.org": true,
	}
	api = &API{
		Database:    sqldb,
		CheckDomain: mockCheckPerform("testequal"),
		List:        mockList{domains: fakeList},
		Emailer:     mockEmailer{},
		DontScan:    map[string]bool{"dontscan.com": true},
	}
	api.parseTemplates()
	mux := http.NewServeMux()
	server = httptest.NewServer(registerHandlers(api, mux))
	defer server.Close()
	code := m.Run()
	os.Exit(code)
}

func teardown() {
	api.Database.ClearTables()
}
