package stats

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	raven "github.com/getsentry/raven-go"
)

// Store wraps storage for MTA-STS adoption statistics.
type Store interface {
	PutAggregatedScan(checker.AggregatedScan) error
	GetMTASTSStats(string) (Series, error)
	GetMTASTSLocalStats() (Series, error)
}

// Import imports JSON list of aggregated scans from a remote server to the
// datastore.
func Import(store Store) {
	statsURL := os.Getenv("REMOTE_STATS_URL")
	resp, err := http.Get(statsURL)
	if err != nil {
		raven.CaptureError(err, nil)
		return
	}
	defer resp.Body.Close()

	var agScans []checker.AggregatedScan
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&agScans)
	if err != nil {
		raven.CaptureError(err, nil)
		return
	}
	for _, a := range agScans {
		err := store.PutAggregatedScan(a)
		if err != nil {
			raven.CaptureError(err, nil)
		}
	}
}

// ImportRegularly runs Import to import aggregated stats from a remote server at regular intervals.
func ImportRegularly(store Store, interval time.Duration) {
	for {
		<-time.After(interval)
		Import(store)
	}
}

// Series represents some statistic as it changes over time.
// This will likely be updated when we know what format our frontend charting
// library prefers.
type Series map[time.Time]float64

const topMillionSource = "majestic-million"

// Get retrieves MTA-STS adoption statistics for user-initiated scans and scans
// of the top million domains over time.
func Get(store Store) (map[string]Series, error) {
	result := make(map[string]Series)
	series, err := store.GetMTASTSStats(topMillionSource)
	if err != nil {
		return result, err
	}
	result["top-million"] = series
	series, err = store.GetMTASTSLocalStats()
	if err != nil {
		return result, err
	}
	result["local"] = series
	return result, err
}
