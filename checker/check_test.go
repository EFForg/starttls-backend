package checker

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalResultJSON(t *testing.T) {
	// Should set description and status_text for CheckResult w/ recognized keys
	result := CheckResult{
		Name:   "starttls",
		Status: Success,
	}
	marshalled, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(marshalled, []byte("\"status_text\":\"Supports")) {
		t.Errorf(string(marshalled))
	}
	if !bytes.Contains(marshalled, []byte("\"description\":\"")) {
		t.Errorf(string(marshalled))
	}

	// Should survive unrecognized keys
	result = CheckResult{
		Name:   "foo",
		Status: 100,
	}
	marshalled, _ = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(marshalled, []byte("\"status_text\":\"")) {
		t.Errorf(string(marshalled))
	}
	if bytes.Contains(marshalled, []byte("\"description\":\"")) {
		t.Errorf(string(marshalled))
	}
}
