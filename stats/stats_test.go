package stats

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

type mockAgScanStore []checker.AggregatedScan

func (m *mockAgScanStore) PutAggregatedScan(agScan checker.AggregatedScan) error {
	*m = append(*m, agScan)
	return nil
}

func (m *mockAgScanStore) PutLocalStats(date time.Time) (checker.AggregatedScan, error) {
	a := checker.AggregatedScan{
		Source: checker.LocalSource,
		Time:   date,
	}
	*m = append(*m, a)
	return a, nil
}

func (m *mockAgScanStore) GetStats(source string) (Series, error) {
	return Series{}, nil
}

func TestImport(t *testing.T) {
	agScans := []checker.AggregatedScan{
		checker.AggregatedScan{
			Time:          time.Now().Add(-24 * time.Hour),
			Attempted:     4,
			WithMXs:       3,
			MTASTSTesting: 2,
			MTASTSEnforce: 1,
		},
		checker.AggregatedScan{
			Time:          time.Now(),
			Attempted:     8,
			WithMXs:       7,
			MTASTSTesting: 6,
			MTASTSEnforce: 5,
		},
	}
	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			enc := json.NewEncoder(w)
			enc.Encode(agScans[0])
			enc.Encode(agScans[1])
		}),
	)
	defer ts.Close()
	os.Setenv("REMOTE_STATS_URL", ts.URL)
	store := mockAgScanStore{}
	err := Import(&store)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range agScans {
		got := store[i]
		// Times must be compared with Time.Equal, so we can't reflect.DeepEqual.
		if !want.Time.Equal(got.Time) {
			t.Errorf("\nExpected\n %v\nGot\n %v", agScans, store)
		}
		if want.PercentMTASTS() != got.PercentMTASTS() {
			t.Errorf("\nExpected\n %v\nGot\n %v", agScans, store)
		}
		if got.Source != checker.TopDomainsSource {
			t.Errorf("Expected source for imported domains to be %s", checker.TopDomainsSource)
		}
	}
}

func TestUpdate(t *testing.T) {
	store := mockAgScanStore{}
	Update(&store)
	a := store[0]
	// Confirm that date is trucated correctly
	if a.Time.Hour() != 0 || a.Time.Minute() != 0 {
		t.Errorf("Expected date to be truncated, got %v", a.Time)
	}
}
