package db_test

import (
	"log"
	"os"
	"strings"
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
	retrievedData, err := database.GetDomain(data.Name, models.StateUnconfirmed)
	if err != nil {
		t.Errorf("GetDomain(%s) failed: %v\n", data.Name, err)
	}
	if retrievedData.Name != data.Name {
		t.Errorf("Somehow, GetDomain retrieved the wrong object?")
	}
	if retrievedData.State != models.StateUnconfirmed {
		t.Errorf("Default state should be 'Unconfirmed'")
	}
}

func TestUpsertDomain(t *testing.T) {
	database.ClearTables()
	data := models.Domain{
		Name:  "testing.com",
		MXs:   []string{"hello1"},
		Email: "admin@testing.com",
	}
	database.PutDomain(data)
	err := database.PutDomain(models.Domain{Name: "testing.com", MXs: []string{"hello_darkness_my_old_friend"}, Email: "actual_admin@testing.com"})
	if err != nil {
		t.Errorf("PutDomain(%s) failed: %v\n", data.Name, err)
	}
	retrievedData, err := database.GetDomain(data.Name, models.StateUnconfirmed)
	if retrievedData.MXs[0] != "hello_darkness_my_old_friend" || retrievedData.Email != "actual_admin@testing.com" {
		t.Errorf("Email and MXs should have been rewritten: %v\n", retrievedData)
	}
}

func TestDomainSetStatus(t *testing.T) {
	// TODO
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
		State: models.StateUnconfirmed,
	}
	database.PutDomain(data)
	retrievedData, _ := database.GetDomain(data.Name, models.StateUnconfirmed)
	lastUpdated := retrievedData.LastUpdated
	data.State = models.StateTesting
	database.PutDomain(models.Domain{Name: data.Name, Email: "new fone who dis"})
	retrievedData, _ = database.GetDomain(data.Name, models.StateUnconfirmed)
	if lastUpdated.Equal(retrievedData.LastUpdated) {
		t.Errorf("Expected last_updated to be updated on change: %v", lastUpdated)
	}
}

func TestLastUpdatedFieldDoesntUpdate(t *testing.T) {
	database.ClearTables()
	data := models.Domain{
		Name:  "testing.com",
		Email: "admin@testing.com",
		State: models.StateUnconfirmed,
	}
	database.PutDomain(data)
	retrievedData, _ := database.GetDomain(data.Name, models.StateUnconfirmed)
	lastUpdated := retrievedData.LastUpdated
	database.PutDomain(data)
	retrievedData, _ = database.GetDomain(data.Name, models.StateUnconfirmed)
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
			database.PutDomain(models.Domain{Name: domain, State: models.StateTesting})
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
	database.SetStatus("x", models.StateTesting)
	database.SetStatus("y", models.StateTesting)
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
	database.ClearTables()

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

func dateMustParse(date string, t *testing.T) time.Time {
	const shortForm = "2006-Jan-02"
	parsed, err := time.Parse(shortForm, date)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestGetStats(t *testing.T) {
	database.ClearTables()
	may1 := dateMustParse("2019-May-01", t)
	may2 := dateMustParse("2019-May-02", t)
	data := []checker.AggregatedScan{
		checker.AggregatedScan{
			Time:          may1,
			Source:        checker.TopDomainsSource,
			Attempted:     5,
			WithMXs:       4,
			MTASTSTesting: 2,
			MTASTSEnforce: 1,
		},
		checker.AggregatedScan{
			Time:          may2,
			Source:        checker.TopDomainsSource,
			Attempted:     10,
			WithMXs:       8,
			MTASTSTesting: 1,
			MTASTSEnforce: 3,
		},
	}
	for _, a := range data {
		err := database.PutAggregatedScan(a)
		if err != nil {
			t.Fatal(err)
		}
	}
	result, err := database.GetStats(checker.TopDomainsSource)
	if err != nil {
		t.Fatal(err)
	}
	if result[0].TotalMTASTS() != 3 || result[1].TotalMTASTS() != 4 {
		t.Errorf("Incorrect MTA-STS stats, got %v", result)
	}
}

func TestPutLocalStats(t *testing.T) {
	database.ClearTables()
	a, err := database.PutLocalStats(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.PercentMTASTS() != 0 {
		t.Errorf("Expected PercentMTASTS with no recent scans to be 0, got %v",
			a.PercentMTASTS())
	}
	day := time.Hour * 24
	today := time.Now()
	lastWeek := today.Add(-6 * day)
	s := models.Scan{
		Domain:    "example1.com",
		Data:      checker.NewSampleDomainResult("example1.com"),
		Timestamp: lastWeek,
	}
	database.PutScan(s)
	a, err = database.PutLocalStats(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.PercentMTASTS() != 100 {
		t.Errorf("Expected PercentMTASTS with one recent scan to be 100, got %v",
			a.PercentMTASTS())
	}
}

func TestGetLocalStats(t *testing.T) {
	database.ClearTables()
	day := time.Hour * 24
	today := time.Now()
	lastWeek := today.Add(-6 * day)

	// Two recent scans from example1.com
	// The most recent scan shows no MTA-STS support.
	s := models.Scan{
		Domain:    "example1.com",
		Data:      checker.NewSampleDomainResult("example1.com"),
		Timestamp: lastWeek.Add(1 * day),
	}
	database.PutScan(s)
	s.Timestamp = lastWeek.Add(3 * day)
	s.Data.MTASTSResult.Mode = ""
	database.PutScan(s)

	// Add another recent scan, from a second domain.
	s = models.Scan{
		Domain:    "example2.com",
		Data:      checker.NewSampleDomainResult("example2.com"),
		Timestamp: lastWeek.Add(2 * day),
	}
	database.PutScan(s)

	// Add a third scan to check that floats are outputted correctly.
	s = models.Scan{
		Domain:    "example3.com",
		Data:      checker.NewSampleDomainResult("example2.com"),
		Timestamp: lastWeek.Add(6 * day),
	}
	database.PutScan(s)

	// Write stats to the database for all the windows we want to check.
	for i := 0; i < 7; i++ {
		database.PutLocalStats(lastWeek.Add(day * time.Duration(i)))
	}

	stats, err := database.GetStats(checker.LocalSource)
	if err != nil {
		t.Fatal(err)
	}

	// Validate result
	expPcts := []float64{0, 100, 100, 50, 50, 50, 100 * 2 / float64(3)}
	if len(expPcts) != 7 {
		t.Errorf("Expected 7 stats, got\n %v\n", stats)
	}
	for i, got := range stats {
		if got.PercentMTASTS() != expPcts[i] {
			t.Errorf("\nExpected %v%%\nGot %v\n (%v%%)", expPcts[i], got, got.PercentMTASTS())
		}
	}
}

func TestGetMTASTSDomains(t *testing.T) {
	database.ClearTables()
	database.PutDomain(models.Domain{Name: "unicorns"})
	database.PutDomain(models.Domain{Name: "mta-sts-x", MTASTS: true})
	database.PutDomain(models.Domain{Name: "mta-sts-y", MTASTS: true})
	database.PutDomain(models.Domain{Name: "regular"})
	domains, err := database.GetMTASTSDomains()
	if err != nil {
		t.Fatalf("GetMTASTSDomains() failed: %v", err)
	}
	if len(domains) != 2 {
		t.Errorf("Expected GetMTASTSDomains() to return 2 elements")
	}
	for _, domain := range domains {
		if !strings.HasPrefix(domain.Name, "mta-sts") {
			t.Errorf("GetMTASTSDomains returned %s when it wasn't supposed to", domain.Name)
		}
	}
}
