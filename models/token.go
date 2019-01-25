package models

import "time"

// Token stores the state of an email verification token.
type Token struct {
	Domain  string    `json:"domain"`  // Domain for which we're verifying the e-mail.
	Token   string    `json:"token"`   // Token that we're expecting.
	Expires time.Time `json:"expires"` // When this token expires.
	Used    bool      `json:"used"`    // Whether this token was used.
}
