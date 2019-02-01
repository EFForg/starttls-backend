package models

import (
	"time"
)

// Subscription stores the subscription information for a domain
type Subscription struct {
	Domain    string
	Email     string
	Token     string
	Confirmed bool
	Timestamp time.Time
}
