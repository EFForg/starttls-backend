package checker

import "fmt"

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
func (c *CheckResult) Error(format string, a ...interface{}) CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Error)
	c.Messages = append(c.Messages, fmt.Sprintf("Error: "+format, a...))
	return *c
}

// Failure adds a failure message to this check result.
// The Failure status will override any Status other than Error.
// Whenever Failure is called, the entire check is failed.
func (c *CheckResult) Failure(format string, a ...interface{}) CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Failure)
	c.Messages = append(c.Messages, fmt.Sprintf("Failure: "+format, a...))
	return *c
}

// Warning adds a warning message to this check result.
// The Warning status only supercedes the Success status.
func (c *CheckResult) Warning(format string, a ...interface{}) CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Warning)
	c.Messages = append(c.Messages, fmt.Sprintf("Warning: "+format, a...))
	return *c
}

// Success simply sets the status of CheckResult to a Success.
// Status is set if no other status has been declared on this check.
func (c *CheckResult) Success() CheckResult {
	c.ensureInit()
	c.Status = SetStatus(c.Status, Success)
	return *c
}

// ResultGroup wraps the results of a security check against a particular hostname.
type ResultGroup struct {
	Status CheckStatus            `json:"status"`
	Checks map[string]CheckResult `json:"checks"`
}

// Returns result of specified check.
// If called before that check occurs, returns false.
func (r ResultGroup) checkSucceeded(checkName string) bool {
	if result, ok := r.Checks[checkName]; ok {
		return result.Status == Success
	}
	return false
}

// Wrapping helper function to set the status of this hostname.
func (r *ResultGroup) addCheck(checkResult CheckResult) {
	r.Checks[checkResult.Name] = checkResult
	// SetStatus sets ResultGroup's status to the most severe of any individual check
	r.Status = SetStatus(r.Status, checkResult.Status)
}
