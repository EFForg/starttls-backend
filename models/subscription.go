package models

import (
	"time"
)

// Subscription stores the STARTTLS security subscription status for a single site.
//
// We allow a single domain to have more than one subscriptions, so long as they are
// with different emails. Each subscription must still be validated via an email to
// postmaster, as a security measure to prevent non-mailserver administrators from
// subcsribing to a particular MTA's security report.
type Subscription struct {
	Domain    string
	Email     string
	Token     string
	Confirmed bool
	Timestamp time.Time
}
