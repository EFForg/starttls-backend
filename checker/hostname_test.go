package checker

import (
	"testing"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}

func TestPolicyMatch(t *testing.T) {
	// Equal matches
	assertEqual(t, policyMatch("example.com", "example.com"), true)
	assertEqual(t, policyMatch("mx.example.com", "mx.example.com"), true)

	// Not equal matches
	assertEqual(t, policyMatch("different.org", "example.com"), false)
	assertEqual(t, policyMatch("not.example.com", "example.com"), false)

	// base domain shouldn't match wildcard
	assertEqual(t, policyMatch("example.com", ".example.com"), false)
	assertEqual(t, policyMatch("*.example.com", "example.com"), false)

	// Invalid wildcard shouldn't match.
	assertEqual(t, policyMatch("*mx.example.com", "mx.example.com"), false)

	// Single-level subdomain match for policy suffix.
	assertEqual(t, policyMatch("mx.example.com", ".example.com"), true)
	assertEqual(t, policyMatch("*.example.com", ".example.com"), true)

	// No multi-level subdomain matching for policy suffix.
	assertEqual(t, policyMatch("mx.mx.example.com", ".example.com"), false)
	assertEqual(t, policyMatch("*.mx.example.com", ".example.com"), false)

	// Role reversal also works.
	assertEqual(t, policyMatch("*.example.com", "mx.example.com"), true)
	assertEqual(t, policyMatch("*.example.com", "mx.mx.example.com"), false)
	assertEqual(t, policyMatch("*.example.com", ".mx.example.com"), false)
}
