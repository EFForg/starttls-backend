package checker

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalResultJSON(t *testing.T) {
	// Should set description and status_text for CheckResult w/ recognized keys
	result := Result{
		Name:   "starttls",
		Status: Success,
	}
	marshalled, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(marshalled, []byte("\"status_text\":\"Success\"")) {
		t.Errorf("Marshalled result should contain status_text, got %s", string(marshalled))
	}
	if !bytes.Contains(marshalled, []byte("\"description\":\"")) {
		t.Errorf("Marshalled result should contain description, got %s", string(marshalled))
	}

	// Should survive unrecognized keys
	result = Result{
		Name:   "foo",
		Status: 100,
	}
	marshalled, _ = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(marshalled, []byte("\"status_text\":\"")) {
		t.Errorf("Result with unrecognized keys shouldn't output status_text, got %s", string(marshalled))
	}
	if bytes.Contains(marshalled, []byte("\"description\":\"")) {
		t.Errorf("Result with unrecognized keys shouldn't output status_text, got %s", string(marshalled))
	}
}
