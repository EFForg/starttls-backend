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

var statusText = map[CheckStatus]string{
	Success: "Success",
	Warning: "Warning",
	Failure: "Failure",
	Error:   "Error",
}

func (r Result) StatusText() string {
	return statusText[r.Status]
}

// SetStatus the resulting status of combining old & new. The order of priority
// for CheckStatus goes: Error > Failure > Warning > Success
func SetStatus(oldStatus CheckStatus, newStatus CheckStatus) CheckStatus {
	if newStatus > oldStatus {
		return newStatus
	}
	return oldStatus
}

// Result is the result of a singular check. It's agnostic to the nature
// of the check performed, and simply stores a reference to the check's name,
// a summary of what the check should do, as well as any error, failure, or
// warning messages associated.
type Result struct {
	Name     string             `json:"name"`
	Status   CheckStatus        `json:"status"`
	Messages []string           `json:"messages,omitempty"`
	Checks   map[string]*Result `json:"checks,omitempty"`
}

// MakeResult constructs a base result object and returns its pointer.
func MakeResult(name string) *Result {
	return &Result{
		Name:     name,
		Status:   Success,
		Messages: make([]string, 0),
		Checks:   make(map[string]*Result),
	}
}

// Error adds an error message to this check result.
// The Error status will override any other existing status for this check.
// Typically, when a check encounters an error, it stops executing.
func (r *Result) Error(format string, a ...interface{}) *Result {
	r.Status = SetStatus(r.Status, Error)
	r.Messages = append(r.Messages, fmt.Sprintf("Error: "+format, a...))
	return r
}

// Failure adds a failure message to this check result.
// The Failure status will override any Status other than Error.
// Whenever Failure is called, the entire check is failed.
func (r *Result) Failure(format string, a ...interface{}) *Result {
	r.Status = SetStatus(r.Status, Failure)
	r.Messages = append(r.Messages, fmt.Sprintf("Failure: "+format, a...))
	return r
}

// Warning adds a warning message to this check result.
// The Warning status only supercedes the Success status.
func (r *Result) Warning(format string, a ...interface{}) *Result {
	r.Status = SetStatus(r.Status, Warning)
	r.Messages = append(r.Messages, fmt.Sprintf("Warning: "+format, a...))
	return r
}

// Success simply sets the status of Result to a Success.
// Status is set if no other status has been declared on this check.
func (r *Result) Success() *Result {
	r.Status = SetStatus(r.Status, Success)
	return r
}

// Returns result of specified check.
// If called before that check occurs, returns false.
func (r *Result) subcheckSucceeded(checkName string) bool {
	if result, ok := r.Checks[checkName]; ok {
		return result.Status == Success
	}
	return false
}

// Wrapping helper function to set the status of this hostname.
func (r *Result) addCheck(checkResult *Result) {
	r.Checks[checkResult.Name] = checkResult
	// SetStatus sets Result's status to the most severe of any individual check
	r.Status = SetStatus(r.Status, checkResult.Status)
}

const (
	Connectivity     = "connectivity"
	STARTTLS         = "starttls"
	Version          = "version"
	Certificate      = "certificate"
	MTASTS           = "mta-sts"
	MTASTSText       = "mta-sts-text"
	MTASTSPolicyFile = "mta-sts-policy-file"
	PolicyList       = "policylist"
)

var checkNames = map[string]string{
	Connectivity:     "Server connectivity",
	STARTTLS:         "Support for STARTTLS",
	Version:          "Secure version of TLS",
	Certificate:      "Valid certificate",
	MTASTS:           "Implementation of MTA-STS",
	MTASTSText:       "Correct MTA-STS DNS record",
	MTASTSPolicyFile: "Correct MTA-STS policy file",
	PolicyList:       "Status on EFF's STARTTLS Everywhere policy list",
}

func (r Result) Description() string {
	return checkNames[r.Name]
}

func (r Result) MarshalJSON() ([]byte, error) {
	// FakeResult lets us access the default json.Marshall result for Result.
	type FakeResult Result
	return json.Marshal(struct {
		FakeResult
		StatusText  string `json:"status_text,omitempty"`
		Description string `json:"description,omitempty"`
	}{
		FakeResult:  FakeResult(r),
		StatusText:  r.StatusText(),
		Description: r.Description(),
	})
}
