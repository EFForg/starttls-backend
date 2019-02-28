package db_test

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/models"
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
	dummyScan := models.Scan{
		Domain:    "dummy.com",
		Data:      checker.DomainResult{Domain: "dummy.com"},
		Timestamp: time.Now(),
		Version:   2,
	}
	err := database.PutScan(dummyScan)
	if err != nil {
		t.Fatalf("PutScan failed: %v\n", err)
	}
	scan, err := database.GetLatestScan("dummy.com")
	if err != nil {
		t.Fatalf("GetLatestScan failed: %v\n", err)
	}
	if dummyScan.Domain != scan.Domain || dummyScan.Data.Domain != scan.Data.Domain ||
		dummyScan.Version != scan.Version ||
		dummyScan.Timestamp.Unix() != dummyScan.Timestamp.Unix() {
		t.Errorf("Expected %v and %v to be the same\n", dummyScan, scan)
	}
}

func TestGetLatestScan(t *testing.T) {
	database.ClearTables()
	// Add two dummy objects
	earlyScan := models.Scan{
		Domain:    "dummy.com",
		Data:      checker.DomainResult{Domain: "dummy.com", Message: "test_before"},
		Timestamp: time.Now(),
	}
	laterScan := models.Scan{
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
	dummyScan := models.Scan{
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
	data := models.Domain{
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
	if retrievedData.State != models.StateUnvalidated {
		t.Errorf("Default state should be 'Unvalidated'")
	}
}

func TestUpsertDomain(t *testing.T) {
	database.ClearTables()
	data := models.Domain{
		Name:  "testing.com",
		Email: "admin@testing.com",
	}
	database.PutDomain(data)
	err := database.PutDomain(models.Domain{Name: "testing.com", State: models.StateQueued})
	if err != nil {
		t.Errorf("PutDomain(%s) failed: %v\n", data.Name, err)
	}
	retrievedData, err := database.GetDomain(data.Name)
	if retrievedData.State != models.StateQueued {
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
	data := models.Domain{
		Name:  "testing.com",
		Email: "admin@testing.com",
		State: models.StateUnvalidated,
	}
	database.PutDomain(data)
	retrievedData, _ := database.GetDomain(data.Name)
	lastUpdated := retrievedData.LastUpdated
	data.State = models.StateQueued
	database.PutDomain(models.Domain{Name: data.Name, Email: "new fone who dis"})
	retrievedData, _ = database.GetDomain(data.Name)
	if lastUpdated.Equal(retrievedData.LastUpdated) {
		t.Errorf("Expected last_updated to be updated on change: %v", lastUpdated)
	}
}

func TestLastUpdatedFieldDoesntUpdate(t *testing.T) {
	database.ClearTables()
	data := models.Domain{
		Name:  "testing.com",
		Email: "admin@testing.com",
		State: models.StateUnvalidated,
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
			database.PutDomain(models.Domain{Name: domain, State: models.StateQueued})
		} else {
			database.PutDomain(models.Domain{Name: domain})
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
	database.PutDomain(models.Domain{Name: "x", MXs: []string{"x.com", "y.org"}})
	database.PutDomain(models.Domain{Name: "y"})
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
	database.ClearTables()
	checksMap := make(map[string]*checker.Result)
	checksMap["test"] = &checker.Result{}
	now := time.Now()
	database.PutHostnameScan("hello",
		checker.HostnameResult{
			Timestamp: now,
			Hostname:  "hello",
			Result:    &checker.Result{Status: 1, Checks: checksMap},
		},
	)
	result, err := database.GetHostnameScan("hello")
	if err != nil {
		t.Errorf("Expected hostname scan to return without errors")
	}
	if now == result.Timestamp {
		t.Errorf("unexpected gap between written timestamp %s and read timestamp %s", now, result.Timestamp)
	}
	if result.Status != 1 || checksMap["test"].Name != result.Checks["test"].Name {
		t.Errorf("Expected hostname scan to return correct data")
	}
}

func TestGetMTASTSStats(t *testing.T) {
	database.ClearTables()
	day := time.Hour * 24
	today := time.Now()
	lastWeek := today.Add(-6 * day)

	// Two recent scans from example1.com
	// The most recent scan shows no MTA-STS support.
	s := models.Scan{
		Domain:    "example1.com",
		Data:      checker.NewSampleDomainResult("example1.com"),
		Timestamp: lastWeek,
	}
	database.PutScan(s)
	s.Timestamp = lastWeek.Add(3 * day)
	s.Data.MTASTSResult.Mode = ""
	database.PutScan(s)
	// Support is shown in the rolling average until the no-support scan is
	// included.
	expectStats(models.TimeSeries{
		lastWeek:              100,
		lastWeek.Add(day):     100,
		lastWeek.Add(2 * day): 100,
		lastWeek.Add(3 * day): 0,
		lastWeek.Add(4 * day): 0,
		lastWeek.Add(5 * day): 0,
		lastWeek.Add(6 * day): 0,
	}, t)

	// Add another recent scan, from a second domain.
	s = models.Scan{
		Domain:    "example2.com",
		Data:      checker.NewSampleDomainResult("example2.com"),
		Timestamp: lastWeek.Add(1 * day),
	}
	database.PutScan(s)
	expectStats(models.TimeSeries{
		lastWeek:              100,
		lastWeek.Add(day):     100,
		lastWeek.Add(2 * day): 100,
		lastWeek.Add(3 * day): 50,
		lastWeek.Add(4 * day): 50,
		lastWeek.Add(5 * day): 50,
		lastWeek.Add(6 * day): 50,
	}, t)

	// Add a third scan to check that floats are outputted correctly.
	s = models.Scan{
		Domain:    "example3.com",
		Data:      checker.NewSampleDomainResult("example2.com"),
		Timestamp: lastWeek.Add(6 * day),
	}
	database.PutScan(s)
	expectStats(models.TimeSeries{
		lastWeek:              100,
		lastWeek.Add(day):     100,
		lastWeek.Add(2 * day): 100,
		lastWeek.Add(3 * day): 50,
		lastWeek.Add(4 * day): 50,
		lastWeek.Add(5 * day): 50,
		lastWeek.Add(6 * day): 66.666664,
	}, t)
}

func expectStats(ts models.TimeSeries, t *testing.T) {
	// GetMTASTSStats returns dates only (no hours, minutes, seconds). We need
	// to truncate the expected times for comparison to dates and convert to UTC
	// to match the database's timezone.
	expected := make(map[time.Time]float32)
	for kOld, v := range ts {
		k := kOld.UTC().Truncate(24 * time.Hour)
		expected[k] = v
	}
	got, err := database.GetMTASTSStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(got) {
		t.Errorf("Expected MTA-STS stats to be\n %v\ngot\n %v\n", expected, got)
		return
	}
	for expKey, expVal := range expected {
		// DB query returns dates only (no hours, minutes, seconds).
		key := expKey.Truncate(24 * time.Hour)
		if got[key] != expVal {
			t.Errorf("Expected MTA-STS stats to be\n %v\ngot\n %v\n", expected, got)
			return
		}
	}
}

func TestPutDomainTotals(t *testing.T) {
	database.ClearTables()
	totals := checker.DomainTotals{
		Time:          time.Now(),
		Source:        "Tom's Domain Emporium",
		Attempted:     1000000000,
		Connected:     10000,
		MTASTSTesting: 1000,
		MTASTSEnforce: 1000,
	}
	err := database.PutDomainTotals(totals)
	if err != nil {
		t.Error(err)
	}
}
