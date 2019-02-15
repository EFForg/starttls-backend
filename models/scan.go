package models

import (
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

// ScanVersion is the version of the Scan API that the binary is currently using.
const ScanVersion = 1

// Scan stores the result of a scan of a domain
type Scan struct {
	Domain    string               `json:"domain"`    // Input domain
	Data      checker.DomainResult `json:"scandata"`  // Scan results from starttls-checker
	Timestamp time.Time            `json:"timestamp"` // Time at which this scan was conducted
	Version   uint32               `json:"version"`   // Version counter
}

// CanAddToPolicyList returns true if the domain owner should be prompted to
// add their domain to the STARTTLS Everywhere Policy List.
func (s Scan) CanAddToPolicyList() bool {
	if policyResult, ok := s.Data.ExtraResults[checker.PolicyList]; ok {
		return s.Data.Status == checker.DomainSuccess &&
			policyResult.Status == checker.Failure
	}
	return false
}

// SupportsMTASTS returns true if the Scan's MTA-STS check passed.
func (s Scan) SupportsMTASTS() bool {
	if s.Data.MTASTSResult == nil {
		return false
	}
	return s.Data.MTASTSResult.Status == checker.Success
}
