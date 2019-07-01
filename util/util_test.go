package util

import "testing"

func TestInvalidPort(t *testing.T) {
	portString, err := ValidPort("8000")
	if err != nil {
		t.Fatalf("Should not have errored on valid string: %v", err)
	}
	if portString != ":8000" {
		t.Fatalf("Expected portstring be :8000 instead of %s", portString)
	}
	portString, err = ValidPort("80a")
	if err == nil {
		t.Fatalf("Expected error on invalid port")
	}
}
