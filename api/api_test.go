package api

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/policy"
	"github.com/joho/godotenv"
)

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
		Database:            sqldb,
		checkDomainOverride: mockCheckPerform("testequal"),
		List:                mockList{domains: fakeList},
		Emailer:             mockEmailer{},
		DontScan:            map[string]bool{"dontscan.com": true},
	}
	api.ParseTemplates("../views")
	mux := http.NewServeMux()
	server = httptest.NewServer(api.RegisterHandlers(mux))
	defer server.Close()
	code := m.Run()
	os.Exit(code)
}

func teardown() {
	api.Database.ClearTables()
}
