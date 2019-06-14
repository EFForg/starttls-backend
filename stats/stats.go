package stats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	raven "github.com/getsentry/raven-go"
)

// Store wraps storage for MTA-STS adoption statistics.
type Store interface {
	PutAggregatedScan(checker.AggregatedScan) error
	PutLocalStats(time.Time) (checker.AggregatedScan, error)
	GetStats(string) (Series, error)
}

// Import imports aggregated scans from a remote server to the datastore.
// Expected format is JSONL (newline-separated JSON objects).
func Import(store Store) error {
	statsURL := os.Getenv("REMOTE_STATS_URL")
	resp, err := http.Get(statsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	s := bufio.NewScanner(resp.Body)
	for s.Scan() {
		var a checker.AggregatedScan
		err := json.Unmarshal(s.Bytes(), &a)
		if err != nil {
			return err
		}
		a.Source = checker.TopDomainsSource
		err = store.PutAggregatedScan(a)
		if err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	return nil
}

// Update imports aggregated scans and updates our cache table of local scans.
// Log any errors.
func Update(store Store) {
	err := Import(store)
	if err != nil {
		err = fmt.Errorf("Failed to import top domains stats: %v", err)
		log.Println(err)
		raven.CaptureError(err, nil)
	}
	// Cache stats for the previous day at midnight. This ensures that we capture
	// full days and maintain regularly intervals.
	_, err = store.PutLocalStats(time.Now().UTC().Truncate(24 * time.Hour))
	if err != nil {
		err = fmt.Errorf("Failed to update local stats: %v", err)
		log.Println(err)
		raven.CaptureError(err, nil)
	}
}

// UpdateRegularly runs Import to import aggregated stats from a remote server at regular intervals.
func UpdateRegularly(store Store, interval time.Duration) {
	for {
		Update(store)
		<-time.After(interval)
	}
}

// Series represents some statistic as it changes over time.
// This will likely be updated when we know what format our frontend charting
// library prefers.
type Series []checker.AggregatedScan

// MarshalJSON marshals a Series to the format expected by chart.js.
// See https://www.chartjs.org/docs/latest/
func (s Series) MarshalJSON() ([]byte, error) {
	type xyPt struct {
		X time.Time `json:"x"`
		Y float64   `json:"y"`
	}
	xySeries := make([]xyPt, 0)
	for _, a := range s {
		var y float64
		if a.Source != checker.TopDomainsSource {
			y = a.PercentMTASTS()
		} else {
			// Top million scans have too few MTA-STS domains to use a percent,
			// display a raw total instead.
			y = float64(a.TotalMTASTS())
		}
		xySeries = append(xySeries, xyPt{X: a.Time, Y: y})
	}
	return json.Marshal(xySeries)
}

// Get retrieves MTA-STS adoption statistics for user-initiated scans and scans
// of the top million domains over time.
func Get(store Store) (result map[string]Series, err error) {
	result = make(map[string]Series)
	sources := []string{checker.TopDomainsSource, checker.LocalSource}
	for _, source := range sources {
		series, err := store.GetStats(source)
		if err != nil {
			return result, err
		}
		result[source] = series
	}
	return result, err
}
