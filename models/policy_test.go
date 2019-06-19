package models

import (
	"errors"
	"strings"
	"testing"

	"github.com/EFForg/starttls-backend/checker"
)

type mockDomainStore struct {
	domain  PolicySubmission
	domains []PolicySubmission
	err     error
}

func (m *mockDomainStore) PutDomain(d PolicySubmission) error {
	m.domain = d
	return m.err
}

func (m *mockDomainStore) SetStatus(d string, status DomainState) error {
	m.domain.State = status
	return m.err
}

func (m *mockDomainStore) GetDomain(d string, state DomainState) (PolicySubmission, error) {
	domain := m.domain
	if state != domain.State {
		return m.domain, errors.New("")
	}
	return m.domain, nil
}

func (m *mockDomainStore) GetDomains(_ DomainState) ([]PolicySubmission, error) {
	return m.domains, m.err
}

func (m *mockDomainStore) RemoveDomain(d string, state DomainState) (PolicySubmission, error) {
	domain := m.domain
	if state != domain.State {
		return m.domain, errors.New("")
	}
	return m.domain, nil
}

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
	d := PolicySubmission{
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
		state   DomainState
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
		{name: "Enforced domain should not be queueable",
			scan: goodScan, scanErr: nil, onList: false, state: StateEnforce,
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
		domainStore := mockDomainStore{domain: PolicySubmission{State: tc.state}}
		ok, msg, _ := d.IsQueueable(&domainStore, mockScanStore{tc.scan, tc.scanErr}, mockList{tc.onList})
		if ok != tc.ok {
			t.Error(tc.name)
		}
		if !strings.Contains(msg, tc.msg) {
			t.Errorf("IsQueueable message should contain %s, got %s", tc.msg, msg)
		}
	}
	// With MTA-STS
	d = PolicySubmission{
		Name:   "example.com",
		Email:  "me@example.com",
		MTASTS: true,
	}
	domainStore := mockDomainStore{err: errors.New("")}
	ok, msg, _ := d.IsQueueable(&domainStore, mockScanStore{goodScan, nil}, mockList{false})
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
	ok, msg, _ = d.IsQueueable(&domainStore, mockScanStore{noMTASTSScan, nil}, mockList{false})
	if ok || !strings.Contains(msg, "MTA-STS") {
		t.Error("Domain without MTA-STS or hostnames should not be queueable, got " + msg)
	}
}

func TestPopulateFromScan(t *testing.T) {
	d := PolicySubmission{
		Name:   "example.com",
		Email:  "me@example.com",
		MTASTS: true,
	}
	s := Scan{
		Data: checker.DomainResult{
			MTASTSResult: checker.MakeMTASTSResult(),
		},
	}
	s.Data.MTASTSResult.MXs = []string{"mx1.example.com", "mx2.example.com"}
	d.PopulateFromScan(s)
	for i, mx := range s.Data.MTASTSResult.MXs {
		if mx != d.MXs[i] {
			t.Errorf("Expected MXs to match scan, got %s", d.MXs)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	var testCases = []struct {
		name     string
		onList   bool
		state    DomainState
		inDB     bool
		expected checker.Status
	}{
		{"Domain on the list should return success", true, StateEnforce, false, checker.Success},
		{"Domain in DB as enforce should return success", false, StateEnforce, true, checker.Success},
		{"Domain queued should return a warning", false, StateTesting, true, checker.Warning},
		{"Unconfirmed domain should return a failure", false, StateUnconfirmed, true, checker.Failure},
		{"Domain not currently in the DB or on the list should return a failure", false, StateUnconfirmed, false, checker.Failure},
	}
	for _, tc := range testCases {
		domainObj := PolicySubmission{Name: "example.com", State: tc.state}
		var dbErr error
		if !tc.inDB {
			dbErr = errors.New("")
		}
		result := domainObj.PolicyListCheck(&mockDomainStore{domain: domainObj, err: dbErr}, mockList{tc.onList})
		if result.Status != tc.expected {
			t.Error(tc.name)
		}
	}
}

func TestInitializeWithToken(t *testing.T) {
	mockToken := mockTokenStore{domain: "domain", err: nil}
	domainObj := PolicySubmission{Name: "example.com"}
	// domainStore returns error
	_, err := domainObj.InitializeWithToken(&mockDomainStore{domain: domainObj, err: errors.New("")}, &mockToken)
	if err == nil {
		t.Error("Expected InitializeWithToken to forward error message from DB")
	}
	if mockToken.token != nil {
		t.Error("Token should not have been set if domain not found")
	}
	_, err = domainObj.InitializeWithToken(&mockDomainStore{domain: domainObj}, &mockTokenStore{err: errors.New("")})
	if err == nil {
		t.Error("Expected InitializeWithToken to forward error message from DB")
	}
	domainObj.InitializeWithToken(&mockDomainStore{domain: domainObj, err: nil}, &mockToken)
	if mockToken.token == nil {
		t.Error("Token should have been set for domain")
	}
}
