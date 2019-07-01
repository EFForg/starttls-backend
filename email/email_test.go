package email

import (
	"os"
	"strings"
	"testing"

	"github.com/EFForg/starttls-backend/util"
)

type mockBlacklistStore struct {
	blacklist map[string]bool
}

func (b *mockBlacklistStore) PutBlacklistedEmail(email string, reason string, timestamp string) error {
	b.blacklist[email] = true
	return nil
}

func (b *mockBlacklistStore) IsBlacklistedEmail(email string) (bool, error) {
	return b.blacklist[email], nil
}

func newMockStore() *mockBlacklistStore {
	return &mockBlacklistStore{
		blacklist: make(map[string]bool),
	}
}

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
	varErrs := util.Errors{}
	util.RequireEnv("FAKE_ENV_VAR", &varErrs)
	if len(varErrs) == 0 {
		t.Errorf("should have received an error")
	}
}

func TestRequireEnvConfig(t *testing.T) {
	requiredVars := map[string]string{
		"SMTP_USERNAME":         "",
		"SMTP_PASSWORD":         "",
		"SMTP_ENDPOINT":         "",
		"SMTP_PORT":             "",
		"SMTP_FROM_ADDRESS":     "",
		"FRONTEND_WEBSITE_LINK": ""}
	for varName := range requiredVars {
		requiredVars[varName] = os.Getenv(varName)
		os.Setenv(varName, "")
	}
	_, err := MakeConfigFromEnv(nil)
	if err == nil {
		t.Errorf("should have received multiple error from unset env vars")
	}
	for varName, varValue := range requiredVars {
		os.Setenv(varName, varValue)
	}
}

func TestSendEmailToBlacklistedAddressFails(t *testing.T) {
	mockStore := newMockStore()
	err := mockStore.PutBlacklistedEmail("fail@example.com", "bounce", "2017-07-21T18:47:13.498Z")
	if err != nil {
		t.Errorf("PutBlacklistedEmail failed: %v\n", err)
	}
	c := &Config{database: mockStore}
	err = c.sendEmail("Subject", "Body", "fail@example.com")
	if err == nil || !strings.Contains(err.Error(), "blacklisted") {
		t.Error("attempting to send mail to blacklisted address should fail")
	}
}
