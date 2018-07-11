package main

import (
	"strings"
	"testing"
)

func TestValidationEmailText(t *testing.T) {
	content := validationEmailText("example.com", "contact@example.com", []string{"mx.example.com, .mx.example.com"}, "abcd", "https://fake.starttls-everywhere.website")
	if !strings.Contains(content, "https://fake.starttls-everywhere.website/validate?abcd") {
		t.Errorf("E-mail formatted incorrectly.")
	}
}

func shouldPanic(t *testing.T, message string) {
	if r := recover(); r == nil {
		t.Errorf(message)
	}
}

func TestRequireMissingEnvPanics(t *testing.T) {
	varErrs := Errors{}
	requireEnv("FAKE_ENV_VAR", &varErrs)
	if len(varErrs) == 0 {
		t.Errorf("should have received an error")
	}
}

func TestRequireEnvConfig(t *testing.T) {
	_, err := makeEmailConfigFromEnv()
	if err == nil {
		t.Errorf("should have received multiple error from unset env vars")
	}
}
