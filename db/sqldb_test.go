package db_test

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/policy"
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

func TestGetNonexistentPolicy(t *testing.T) {
	database.ClearTables()
	_, ok, err := database.Policies.GetPolicy("fake")
	if err != nil || ok {
		t.Errorf("Expected nothing to return and ok to be false.")
	}
}

func TestGetPoliciesEmpty(t *testing.T) {
	database.ClearTables()
	_, err := database.Policies.GetPolicies(false)
	if err != nil {
		t.Errorf("Get policies failed: %v", err)
	}
	err = database.Policies.PutOrUpdatePolicy(&models.PolicySubmission{Name: "abcde", MTASTS: true})
	policies, err := database.Policies.GetPolicies(false)
	if len(policies) > 0 {
		t.Errorf("Should not have returned any policies.")
	}
	if err != nil {
		t.Errorf("Get policies failed: %v", err)
	}
}

func TestPutGetDomain(t *testing.T) {
	database.ClearTables()
	data := models.PolicySubmission{
		Name:   "testing.com",
		Email:  "admin@testing.com",
		Policy: &policy.TLSPolicy{MXs: []string{}, Mode: "testing"},
	}
	err := database.Policies.PutOrUpdatePolicy(&data)
	if err != nil {
		t.Errorf("PutDomain failed: %v\n", err)
	}
	retrievedData, ok, err := database.Policies.GetPolicy(data.Name)
	if !ok || err != nil {
		t.Fatalf("GetDomain(%s) failed: %v\n", data.Name, err)
	}
	if retrievedData.Name != data.Name {
		t.Errorf("Somehow, GetDomain retrieved the wrong object?")
	}
}

func TestUpsertDomain(t *testing.T) {
	database.ClearTables()
	var getPolicy = func(email string, mx string) *models.PolicySubmission {
		return &models.PolicySubmission{
			Name:   "testing.com",
			Policy: &policy.TLSPolicy{MXs: []string{mx}, Mode: "testing"},
			Email:  email,
		}
	}
	database.Policies.PutOrUpdatePolicy(getPolicy("admin@testing.com", "hello1"))
	err := database.Policies.PutOrUpdatePolicy(getPolicy("actual_admin@testing.com", "hello_darkness_my_old_friend"))
	if err != nil {
		t.Errorf("PutDomain(%s) failed: %v\n", "testing.com", err)
	}
	retrievedData, ok, err := database.Policies.GetPolicy("testing.com")
	if !ok || err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if retrievedData.Policy.MXs[0] != "hello_darkness_my_old_friend" || retrievedData.Email != "actual_admin@testing.com" {
		t.Errorf("Email and MXs should have been rewritten: %v\n", retrievedData)
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

func TestDomainsToValidate(t *testing.T) {
	database.ClearTables()
	mtastsMap := map[string]bool{
		"a": false, "b": true, "c": false, "d": true,
	}
	for domain, mtasts := range mtastsMap {
		if mtasts {
			database.Policies.PutOrUpdatePolicy(&models.PolicySubmission{Name: domain, MTASTS: true})
		} else {
			database.Policies.PutOrUpdatePolicy(&models.PolicySubmission{Name: domain})
		}
	}
	result, err := database.DomainsToValidate()
	if err != nil {
		t.Fatalf("DomainsToValidate failed: %v\n", err)
	}
	for _, domain := range result {
		if !mtastsMap[domain] {
			t.Errorf("Did not expect %s to be returned", domain)
		}
	}
}

func TestHostnamesForDomain(t *testing.T) {
	database.ClearTables()
	database.PendingPolicies.PutOrUpdatePolicy(&models.PolicySubmission{Name: "x",
		Policy: &policy.TLSPolicy{Mode: "testing", MXs: []string{"x.com", "y.org"}}})
	database.Policies.PutOrUpdatePolicy(&models.PolicySubmission{Name: "y",
		Policy: &policy.TLSPolicy{Mode: "testing", MXs: []string{}}})
	result, err := database.HostnamesForDomain("x")
	if err != nil {
		t.Fatalf("HostnamesForDomain failed: %v\n", err)
	}
	if len(result) != 2 || result[0] != "x.com" || result[1] != "y.org" {
		t.Errorf("Expected two hostnames, x.com and y.org\n")
	}
	result, err = database.HostnamesForDomain("y")
	if err == nil {
		t.Errorf("HostnamesForDomain should fail for y\n")
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
