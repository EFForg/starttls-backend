package db_test

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
	"github.com/joho/godotenv"
)

// Global database object for tests.
var database *db.SQLDatabase

// Connects to local test db.
func initTestDb() *db.SQLDatabase {
	os.Setenv("PRIV_KEY", "./certs/key.pem")
	os.Setenv("PUBLIC_KEY", "./certs/cert.pem")
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	database, err := db.InitSQLDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return database
}

func TestMain(m *testing.M) {
	godotenv.Overload("../.env.test")
	database = initTestDb()
	code := m.Run()
	err := database.ClearTables()
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(code)
}

////////////////////////////////
// ***** Database tests ***** //
////////////////////////////////

func TestPutScan(t *testing.T) {
	database.ClearTables()
	dummyScan := db.ScanData{
		Domain:    "dummy.com",
		Data:      checker.DomainResult{Domain: "dummy.com"},
		Timestamp: time.Now(),
	}
	err := database.PutScan(dummyScan)
	if err != nil {
		t.Errorf("PutScan failed: %v\n", err)
	}
}

func TestGetLatestScan(t *testing.T) {
	database.ClearTables()
	// Add two dummy objects
	earlyScan := db.ScanData{
		Domain:    "dummy.com",
		Data:      checker.DomainResult{Domain: "dummy.com", Message: "test_before"},
		Timestamp: time.Now(),
	}
	laterScan := db.ScanData{
		Domain:    "dummy.com",
		Data:      checker.DomainResult{Domain: "dummy.com", Message: "test_after"},
		Timestamp: time.Now().Add(time.Duration(time.Hour)),
	}
	err := database.PutScan(laterScan)
	if err != nil {
		t.Errorf("PutScan failed: %v\n", err)
	}
	err = database.PutScan(earlyScan)
	if err != nil {
		t.Errorf("PutScan failed: %v\n", err)
	}
	scan, err := database.GetLatestScan("dummy.com")
	if err != nil {
		t.Errorf("GetLatestScan failed: %v\n", err)
	}
	if scan.Data.Message != "test_after" {
		t.Errorf("Expected GetLatestScan to retrieve most recent scanData: %v", scan)
	}
}

func TestGetAllScans(t *testing.T) {
	database.ClearTables()
	data, err := database.GetAllScans("dummy.com")
	if err != nil {
		t.Errorf("GetAllScans failed: %v\n", err)
	}
	// Retrieving scans for domain that's never been scanned before
	if len(data) != 0 {
		t.Errorf("Expected GetAllScans to return []")
	}
	// Add two dummy objects
	dummyScan := db.ScanData{
		Domain:    "dummy.com",
		Data:      checker.DomainResult{Domain: "dummy.com", Message: "test1"},
		Timestamp: time.Now(),
	}
	err = database.PutScan(dummyScan)
	if err != nil {
		t.Errorf("PutScan failed: %v\n", err)
	}
	dummyScan.Data.Message = "test2"
	err = database.PutScan(dummyScan)
	if err != nil {
		t.Errorf("PutScan failed: %v\n", err)
	}
	data, err = database.GetAllScans("dummy.com")
	// Retrieving scans for domain that's been scanned once
	if err != nil {
		t.Errorf("GetAllScans failed: %v\n", err)
	}
	if len(data) != 2 {
		t.Errorf("Expected GetAllScans to return two items, returned %d\n", len(data))
	}
	if data[0].Data.Message != "test1" || data[1].Data.Message != "test2" {
		t.Errorf("Expected Data of scan objects to include both test1 and test2")
	}
}

func TestPutGetDomain(t *testing.T) {
	database.ClearTables()
	data := db.DomainData{
		Name:  "testing.com",
		Email: "admin@testing.com",
	}
	err := database.PutDomain(data)
	if err != nil {
		t.Errorf("PutDomain failed: %v\n", err)
	}
	retrievedData, err := database.GetDomain(data.Name)
	if err != nil {
		t.Errorf("GetDomain(%s) failed: %v\n", data.Name, err)
	}
	if retrievedData.Name != data.Name {
		t.Errorf("Somehow, GetDomain retrieved the wrong object?")
	}
	if retrievedData.State != db.StateUnvalidated {
		t.Errorf("Default state should be 'Unvalidated'")
	}
}

func TestUpsertDomain(t *testing.T) {
	database.ClearTables()
	data := db.DomainData{
		Name:  "testing.com",
		Email: "admin@testing.com",
	}
	database.PutDomain(data)
	err := database.PutDomain(db.DomainData{Name: "testing.com", State: db.StateQueued})
	if err != nil {
		t.Errorf("PutDomain(%s) failed: %v\n", data.Name, err)
	}
	retrievedData, err := database.GetDomain(data.Name)
	if retrievedData.State != db.StateQueued {
		t.Errorf("Expected state to be 'Queued', was %v\n", retrievedData)
	}
}

func TestPutUseToken(t *testing.T) {
	database.ClearTables()
	data, err := database.PutToken("testing.com")
	if err != nil {
		t.Errorf("PutToken failed: %v\n", err)
	}
	domain, err := database.UseToken(data.Token)
	if err != nil {
		t.Errorf("UseToken failed: %v\n", err)
	}
	if domain != data.Domain {
		t.Errorf("UseToken used token for %s instead of %s\n", domain, data.Domain)
	}
}

func TestPutTokenTwice(t *testing.T) {
	database.ClearTables()
	data, err := database.PutToken("testing.com")
	if err != nil {
		t.Errorf("PutToken failed: %v\n", err)
	}
	_, err = database.PutToken("testing.com")
	if err != nil {
		t.Errorf("PutToken failed: %v\n", err)
	}
	domain, err := database.UseToken(data.Token)
	if domain == data.Domain {
		t.Errorf("UseToken should not have succeeded with old token!\n")
	}
}

func TestLastUpdatedFieldUpdates(t *testing.T) {
	database.ClearTables()
	data := db.DomainData{
		Name:  "testing.com",
		Email: "admin@testing.com",
		State: db.StateUnvalidated,
	}
	database.PutDomain(data)
	retrievedData, _ := database.GetDomain(data.Name)
	lastUpdated := retrievedData.LastUpdated
	data.State = db.StateQueued
	database.PutDomain(db.DomainData{Name: data.Name, Email: "new fone who dis"})
	retrievedData, _ = database.GetDomain(data.Name)
	if lastUpdated.Equal(retrievedData.LastUpdated) {
		t.Errorf("Expected last_updated to be updated on change: %v", lastUpdated)
	}
}

func TestLastUpdatedFieldDoesntUpdate(t *testing.T) {
	database.ClearTables()
	data := db.DomainData{
		Name:  "testing.com",
		Email: "admin@testing.com",
		State: db.StateUnvalidated,
	}
	database.PutDomain(data)
	retrievedData, _ := database.GetDomain(data.Name)
	lastUpdated := retrievedData.LastUpdated
	database.PutDomain(data)
	retrievedData, _ = database.GetDomain(data.Name)
	if !lastUpdated.Equal(retrievedData.LastUpdated) {
		t.Errorf("Expected last_updated to stay the same if no changes were made")
	}
}

func TestDomainsToValidate(t *testing.T) {
	database.ClearTables()
	queuedMap := map[string]bool{
		"a": false, "b": true, "c": false, "d": true,
	}
	for domain, queued := range queuedMap {
		if queued {
			database.PutDomain(db.DomainData{Name: domain, State: db.StateQueued})
		} else {
			database.PutDomain(db.DomainData{Name: domain})
		}
	}
	result, err := database.DomainsToValidate()
	if err != nil {
		t.Fatalf("DomainsToValidate failed: %v\n", err)
	}
	for _, domain := range result {
		if !queuedMap[domain] {
			t.Errorf("Did not expect %s to be returned", domain)
		}
	}
}

func TestHostnamesForDomain(t *testing.T) {
	database.ClearTables()
	database.PutDomain(db.DomainData{Name: "x", MXs: []string{"x.com", "y.org"}})
	database.PutDomain(db.DomainData{Name: "y"})
	result, err := database.HostnamesForDomain("x")
	if err != nil {
		t.Fatalf("HostnamesForDomain failed: %v\n", err)
	}
	if len(result) != 2 || result[0] != "x.com" || result[1] != "y.org" {
		t.Errorf("Expected two hostnames, x.com and y.org\n")
	}
	result, err = database.HostnamesForDomain("y")
	if err != nil {
		t.Fatalf("HostnamesForDomain failed: %v\n", err)
	}
	if len(result) > 0 {
		t.Errorf("Expected no hostnames to be returned, got %s\n", result[0])
	}
}

func TestPutAndIsBlacklistedEmail(t *testing.T) {
	defer database.ClearTables()

	// Add an e-mail address to the blacklist.
	err := database.PutBlacklistedEmail("fail@example.com", "bounce", "2017-07-21T18:47:13.498Z")
	if err != nil {
		t.Errorf("PutBlacklistedEmail failed: %v\n", err)
	}

	// Check that the email address was blacklisted.
	blacklisted, err := database.IsBlacklistedEmail("fail@example.com")
	if err != nil {
		t.Errorf("IsBlacklistedEmail failed: %v\n", err)
	}
	if !blacklisted {
		t.Errorf("fail@example.com should be blacklisted, but wasn't")
	}

	// Check that an un-added email address is not blacklisted.
	blacklisted, err = database.IsBlacklistedEmail("good@example.com")
	if err != nil {
		t.Errorf("IsBlacklistedEmail failed: %v\n", err)
	}
	if blacklisted {
		t.Errorf("good@example.com should not be blacklisted, but was")
	}
}

func TestGetHostnameScan(t *testing.T) {
	checksMap := make(map[string]checker.CheckResult)
	checksMap["test"] = checker.CheckResult{}
	now := time.Now()
	database.PutHostnameScan("hello",
		checker.HostnameResult{
			Timestamp:   time.Now(),
			Hostname:    "hello",
			ResultGroup: &checker.ResultGroup{Status: 1, Checks: checksMap},
		},
	)
	result, err := database.GetHostnameScan("hello")
	if err != nil {
		t.Errorf("Expected hostname scan to return without errors")
	}
	if now.Sub(result.Timestamp) > time.Second {
		t.Errorf("unexpected gap between written timestamp %s and read timestamp %s", now, result.Timestamp)
	}
	if result.Status != 1 || checksMap["test"].Name != result.Checks["test"].Name {
		t.Errorf("Expected hostname scan to return correct data")
	}
}
