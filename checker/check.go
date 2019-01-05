package checker

import (
	"encoding/json"
	"fmt"
)

// CheckStatus is an enum encoding the status of the overall check.
type CheckStatus int32

// Values for CheckStatus
const (
	Success CheckStatus = 0
	Warning CheckStatus = 1
	Failure CheckStatus = 2
	Error   CheckStatus = 3
)

// SetStatus the resulting status of combining old & new. The order of priority
// for CheckStatus goes: Error > Failure > Warning > Success
func SetStatus(oldStatus CheckStatus, newStatus CheckStatus) CheckStatus {
	if newStatus > oldStatus {
		return newStatus
	}
	return oldStatus
}

// CheckResult the result of a singular check. It's agnostic to the nature
// of the check performed, and simply stores a reference to the check's name,
// a summary of what the check should do, as well as any error, failure, or
// warning messages associated.
type CheckResult struct {
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Messages []string    `json:"messages,omitempty"`
}

// Ensures the Messages field is initialized.
func (c *CheckResult) ensureInit() {
	if c.Messages == nil {
		c.Messages = make([]string, 0)
	}
}

// Error adds an error message to this check result.
// The Error status will override any other existing status for this check.
// Typically, when a check encounters an error, it stops executing.
func (c CheckResult) Error(format string, a ...interface{}) CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Error)
	c.Messages = append(c.Messages, fmt.Sprintf("Error: "+format, a...))
	return c
}

// Failure adds a failure message to this check result.
// The Failure status will override any Status other than Error.
// Whenever Failure is called, the entire check is failed.
func (c CheckResult) Failure(format string, a ...interface{}) CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Failure)
	c.Messages = append(c.Messages, fmt.Sprintf("Failure: "+format, a...))
	return c
}

// Warning adds a warning message to this check result.
// The Warning status only supercedes the Success status.
func (c CheckResult) Warning(format string, a ...interface{}) CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Warning)
	c.Messages = append(c.Messages, fmt.Sprintf("Warning: "+format, a...))
	return c
}

// Success simply sets the status of CheckResult to a Success.
// Status is set if no other status has been declared on this check.
func (c CheckResult) Success() CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Success)
	return c
}

// MarshalJSON specifies how json.Marshall should handle type CheckResult.
// Adds status_text and description fields to the default output.
func (c CheckResult) MarshalJSON() ([]byte, error) {
	// FakeCheckResult lets us access the default json.Marshall result for CheckResult.
	type FakeCheckResult CheckResult
	return json.Marshal(struct {
		FakeCheckResult
		StatusText  string `json:"status_text,omitempty"`
		Description string `json:"description,omitempty"`
	}{
		FakeCheckResult: FakeCheckResult(c),
		StatusText:      c.StatusText(),
		Description:     c.Description(),
	})
}

// StatusText returns a human-readable status string
func (c CheckResult) StatusText() string {
	if checkType, ok := checkTypes[c.Name]; ok {
		if statusText, ok := checkType.StatusText[c.Status]; ok {
			return statusText
		}
	}
	return ""
}

// Description returns a technical description of the check that was
// performed.
func (c CheckResult) Description() string {
	if checkType, ok := checkTypes[c.Name]; ok {
		return checkType.Description
	}
	return ""
}

// CheckTypes stores descriptive information about the types of check that can
// be performed by the Checker.
type CheckTypes map[string]CheckType

// CheckType stores descriptive information about a single type of check that
// can be performed by the Checker.
type CheckType struct {
	StatusText
	Description string
}

// StatusText maps CheckStatus codes to human-readable strings.
type StatusText map[CheckStatus]string

var checkTypes = CheckTypes{
	"starttls": CheckType{
		StatusText: StatusText{
			Success: "Supports STTARTTLS",
			Failure: "Does not support STARTTLS",
		},
		Description: `“STARTTLS” is the command an email server sends if it wants to encrypt communications (using Transport Layer Security or “TLS”) with another email server. If your server supports STARTTLS, that means any other server that supports STARTTLS can communicate securely with it.

This checks that your email server sends the STARTTLS command correctly, as well as accepting the STARTTLS command from other servers.`,
	},
	"version": CheckType{
		StatusText: StatusText{
			Success: "Uses a secure version of TLS",
			Failure: "Does not use a secure TLS version",
		},
		Description: `TLS has changed many times over the years. Researchers have discovered security flaws in some older versions, named “SSLv2” and “SSLv3”, so technologists across the internet are <a href="https://disablessl3.com/" target="_blank">working to deprecate</a> SSLv2/3.

This checks that your email server does not allow establishing a valid TLS connection over SSLv2/3.`,
	},
	"certificate": CheckType{
		StatusText: StatusText{
			Success: "Presents a valid certificate",
			Failure: "Does not present a valid certificate",
		},
		Description: `On the internet, even if you *think* you’re talking to a service named “eff.org”, it could be an impersonator pretending to be “eff.org”. Checking a mail server’s certificate helps ensure that you really are talking to the actual service.

In order for your certificate to be valid for your email domain, it should be unexpired, chain to a <a href="https://wiki.mozilla.org/CA/Included_Certificates" target="_blank">valid root</a>, and one of the names on the certificate should either match the domain (the part of an email address after the @) or the server’s hostname (the name of the server, as indicated by an MX record).`,
	},
	"connectivity": CheckType{
		StatusText: StatusText{
			Success: "Server is up and running",
			Failure: "Could not establish connection",
		},
		Description: `We couldn't successfully connect to this mailserver to scan it. This could be an error on our side, too. If you're having trouble getting the scanner to work, shoot us an email at <a href="mailto:starttls-policy@eff.org">starttls-policy@eff.org</a>.`,
	},
}
