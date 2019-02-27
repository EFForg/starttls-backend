package models

import "time"

// TimeSeries holds dates with associated numerical values, for charting.
type TimeSeries map[time.Time]float32
