package models

import (
	"errors"
	"strings"
	"testing"

	"github.com/EFForg/starttls-backend/checker"
)

type mockList struct {
	hasDomain bool
}

func (m mockList) HasDomain(string) bool { return m.hasDomain }

type mockScanStore struct {
	scan Scan
	err  error
}

func (m mockScanStore) GetLatestScan(string) (Scan, error) { return m.scan, m.err }

func TestIsQueueable(t *testing.T) {
	d := Domain{
		Name:  "example.com",
		Email: "me@example.com",
		MXs:   []string{"mx1.example.com", "mx2.example.com"},
	}
	ok, msg := d.IsQueueable(mockScanStore{Scan{}, nil}, mockList{false})
	if !ok {
		t.Error("Unadded domain with passing scan should be queueable")
	}
	ok, msg = d.IsQueueable(mockScanStore{Scan{}, nil}, mockList{true})
	if ok || !strings.Contains(msg, "already on the policy list") {
		t.Error("Domain on policy list should not be queueable")
	}
	failedScan := Scan{
		Data: checker.DomainResult{Status: checker.DomainFailure},
	}
	ok, msg = d.IsQueueable(mockScanStore{failedScan, nil}, mockList{false})
	if ok || !strings.Contains(msg, "hasn't passed") {
		t.Error("Domain with failing scan should not be queueable")
	}
	ok, msg = d.IsQueueable(mockScanStore{Scan{}, errors.New("")}, mockList{false})
	if ok || !strings.Contains(msg, "haven't scanned") {
		t.Error("Domain without scan should not be queueable")
	}
}
