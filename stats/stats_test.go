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

func (m *mockAgScanStore) GetMTASTSStats(source string) (Series, error) {
	return Series{}, nil
}

func (m *mockAgScanStore) GetMTASTSLocalStats() (Series, error) {
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
			json.NewEncoder(w).Encode(agScans)
		}),
	)
	os.Setenv("REMOTE_STATS_URL", ts.URL)
	store := mockAgScanStore{}
	Import(&store)
	for i, want := range agScans {
		got := store[i]
		// Times must be compared with Time.Equal, so we can't reflect.DeepEqual.
		if !want.Time.Equal(got.Time) {
			t.Errorf("\nExpected\n %v\nGot\n %v", agScans, store)
		}
		if want.PercentMTASTS() != got.PercentMTASTS() {
			t.Errorf("\nExpected\n %v\nGot\n %v", agScans, store)
		}
		if got.Source != topDomainsSource {
			t.Errorf("Expected source for imported domains to be %s", topDomainsSource)
		}
	}
}
