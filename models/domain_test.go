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
	// With supplied hostnames
	d := Domain{
		Name:  "example.com",
		Email: "me@example.com",
		MXs:   []string{".example.com"},
	}
	goodScan := Scan{
		Data: checker.DomainResult{
			PreferredHostnames: []string{"mx1.example.com", "mx2.example.com"},
			MTASTSResult:       checker.MakeMTASTSResult(),
		},
	}
	failedScan := Scan{
		Data: checker.DomainResult{Status: checker.DomainFailure},
	}
	wrongMXsScan := Scan{
		Data: checker.DomainResult{
			PreferredHostnames: []string{"mx1.nomatch.example.com"},
		},
	}
	var testCases = []struct {
		name    string
		scan    Scan
		scanErr error
		onList  bool
		ok      bool
		msg     string
	}{
		{name: "Unadded domain with passing scan should be queueable",
			scan: goodScan, scanErr: nil, onList: false,
			ok: true, msg: ""},
		{name: "Domain on policy list should not be queueable",
			scan: goodScan, scanErr: nil, onList: true,
			ok: false, msg: "already on the policy list"},
		{name: "Domain with failing scan should not be queueable",
			scan: failedScan, scanErr: nil, onList: false,
			ok: false, msg: "hasn't passed"},
		{name: "Domain without scan should not be queueable",
			scan: goodScan, scanErr: errors.New(""), onList: false,
			ok: false, msg: "haven't scanned"},
		{name: "Domain with mismatched hostnames should not be queueable",
			scan: wrongMXsScan, scanErr: nil, onList: false,
			ok: false, msg: "do not match policy"},
	}
	for _, tc := range testCases {
		ok, msg, _ := d.IsQueueable(mockScanStore{tc.scan, tc.scanErr}, mockList{tc.onList})
		if ok != tc.ok {
			t.Error(tc.name)
		}
		if !strings.Contains(msg, tc.msg) {
			t.Errorf("IsQueueable message should contain %s, got %s", tc.msg, msg)
		}
	}
	// With MTA-STS
	d = Domain{
		Name:       "example.com",
		Email:      "me@example.com",
		MTASTSMode: "on",
	}
	ok, msg, _ := d.IsQueueable(mockScanStore{goodScan, nil}, mockList{false})
	if !ok {
		t.Error("Unadded domain with passing scan should be queueable, got " + msg)
	}
	noMTASTSScan := Scan{
		Data: checker.DomainResult{
			MTASTSResult: &checker.MTASTSResult{
				Result: &checker.Result{
					Status: checker.Failure,
				},
			},
		},
	}
	ok, msg, _ = d.IsQueueable(mockScanStore{noMTASTSScan, nil}, mockList{false})
	if ok || !strings.Contains(msg, "MTA-STS") {
		t.Error("Domain without MTA-STS or hostnames should not be queueable, got " + msg)
	}
}

func TestPopulateFromScan(t *testing.T) {
	d := Domain{
		Name:  "example.com",
		Email: "me@example.com",
	}
	s := Scan{
		Data: checker.DomainResult{
			MTASTSResult: checker.MakeMTASTSResult(),
		},
	}
	s.Data.MTASTSResult.Mode = "enforce"
	s.Data.MTASTSResult.MXs = []string{"mx1.example.com", "mx2.example.com"}
	d.PopulateFromScan(s)
	if d.MTASTSMode != "enforce" {
		t.Errorf("Expected domain MTA-STS mode to match scan, got %s", d.MTASTSMode)
	}
	for i, mx := range s.Data.MTASTSResult.MXs {
		if mx != d.MXs[i] {
			t.Errorf("Expected MXs to match scan, got %s", d.MXs)
		}
	}
}
