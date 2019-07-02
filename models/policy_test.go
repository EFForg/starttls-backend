package models

import (
	"errors"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/policy"
	"testing"
)

type mockPolicyStore struct {
	policy   PolicySubmission
	ok       bool
	policies []PolicySubmission
	err      error
}

func (m *mockPolicyStore) PutOrUpdatePolicy(p *PolicySubmission) error {
	m.policy = *p
	return m.err
}

func (m *mockPolicyStore) GetPolicy(domain string) (PolicySubmission, bool, error) {
	return m.policy, m.ok, m.err
}

func (m *mockPolicyStore) GetPolicies(_ bool) ([]PolicySubmission, error) {
	return m.policies, m.err
}

func (m *mockPolicyStore) RemovePolicy(_ string) (PolicySubmission, error) {
	policy := m.policy
	m.policy.Name = "-removed-"
	return policy, m.err
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

// Some helper functions to make constructing dummy objects easier

func (p PolicySubmission) withMode(mode string) PolicySubmission {
	p.Policy.Mode = mode
	return p
}

func (p PolicySubmission) withMXs(mxs []string) PolicySubmission {
	p.Policy.MXs = mxs
	return p
}

func (p PolicySubmission) withMTASTS() PolicySubmission {
	p.MTASTS = true
	return p
}

func (p PolicySubmission) withEmail(email string) PolicySubmission {
	p.Email = email
	return p
}

func TestSamePolicy(t *testing.T) {
	empty := PolicySubmission{}
	var initialized = func() PolicySubmission {
		return PolicySubmission{Policy: &policy.TLSPolicy{}}
	}
	var testCases = []struct {
		desc     string
		policy   PolicySubmission
		other    PolicySubmission
		expected bool
	}{
		{"Empty structs equal", empty, empty, true},
		{"Names unequal", PolicySubmission{Name: "hello"}, PolicySubmission{Name: "nope"}, false},
		{"MTASTS structs equal", empty.withMTASTS(), empty.withMTASTS(), true},
		{"Modes not equal", initialized().withMode("testing"), initialized().withMode("enforce"), false},
		{"Modes equal", initialized().withMode("testing"), initialized().withMode("testing"), true},
		{"MXs equal",
			initialized().withMXs([]string{"a", "b", "c"}),
			initialized().withMXs([]string{"b", "c", "a"}), true},
		{"MXs not equal",
			initialized().withMXs([]string{"a", "b"}),
			initialized().withMXs([]string{"b", "c", "a"}), false},
		{"MXs equal but mode unequal",
			initialized().withMode("enforce").withMXs([]string{"a", "b", "c"}),
			initialized().withMode("testing").withMXs([]string{"b", "c", "a"}), false},
	}
	for _, tc := range testCases {
		got := (&tc.policy).samePolicy(tc.other)
		if got != tc.expected {
			t.Errorf("%s: expected %t, got %t", tc.desc, tc.expected, got)
		}
	}
}

func TestCanUpdate(t *testing.T) {
	var newP = func() PolicySubmission {
		return PolicySubmission{Policy: &policy.TLSPolicy{}}
	}
	var testCases = []struct {
		desc      string
		oldPolicy PolicySubmission // Return from GetPolicy
		policy    PolicySubmission // Policy to try to insert
		ok        bool             // Does GetPolicy return OK?
		err       error            // Does GetPolicy return an error?
		expected  bool
	}{
		{"policy not found", newP(), newP(), false, nil, true},
		{"DB throws error", newP(), newP(), false, errors.New("Oh no"), false},
		{"no update if policies same 1", newP().withMode("testing"), newP().withMode("testing"), true, nil, false},
		{"no update if policies same 2", newP().withMode("enforce"), newP().withMode("enforce"), true, nil, false},
		{"no update if policies same 3",
			newP().withMode("enforce").withMTASTS().withMXs([]string{"a", "b", "c"}),
			newP().withMode("enforce").withMTASTS().withMXs([]string{"a", "c", "b"}),
			true, nil, false},
		{"can upgrade to manual enforce", newP().withMode("testing"), newP().withMode("enforce"), true, nil, false},
		{"can't downgrade to enforce", newP().withMode("enforce"), newP().withMode("testing"), true, nil, false},
		{"prevent upgrade to enforce with MTA-STS",
			newP().withMTASTS().withMode("testing"),
			newP().withMode("enforce"),
			true, nil, false},
		{"no mx changes with MTA-STS, even in testing",
			newP().withMTASTS().withMode("testing").withMXs([]string{"a", "b"}),
			newP().withMTASTS().withMode("testing").withMXs([]string{"a", "b", "c"}),
			true, nil, false},
		{"mx can change in testing",
			newP().withMode("testing").withMXs([]string{"a", "b"}),
			newP().withMode("testing").withMXs([]string{"a", "b", "c"}),
			true, nil, true},
		{"update email", newP().withEmail("abc").withMode("enforce"), newP().withEmail("a").withMode("enforce"),
			true, nil, true},
	}
	for _, tc := range testCases {
		store := mockPolicyStore{policy: tc.oldPolicy, err: tc.err, ok: tc.ok}
		got := (&tc.policy).CanUpdate(&store)
		if got != tc.expected {
			t.Errorf("%s: expected %t but got %t",
				tc.desc, tc.expected, got)
		}
	}
}

func TestValidScan(t *testing.T) {
	var newP = PolicySubmission{
		Name:  "example.com",
		Email: "me@example.com",
		Policy: &policy.TLSPolicy{
			Mode: "testing",
			MXs:  []string{".example.com"}}}

	goodScan := Scan{
		Data: checker.DomainResult{
			PreferredHostnames: []string{"mx1.example.com", "mx2.example.com"},
			MTASTSResult:       checker.MakeMTASTSResult(),
		},
		Timestamp: time.Now()}
	var withBadMTASTS = func(scan Scan) Scan {
		scan.Data.MTASTSResult = checker.MakeMTASTSResult()
		scan.Data.MTASTSResult.Status = checker.Failure
		return scan
	}
	var withTimestamp = func(scan Scan, time time.Time) Scan {
		scan.Timestamp = time
		return scan
	}
	failedScan := Scan{
		Data:      checker.DomainResult{Status: checker.DomainFailure},
		Timestamp: time.Now()}
	var testCases = []struct {
		desc     string
		mxs      []string
		mtasts   bool
		scan     Scan
		err      error
		expected bool
	}{
		{desc: "Unadded domain with recent passing scan should be queueable",
			mxs: []string{".example.com"}, scan: goodScan, err: nil, expected: true},
		{desc: "Unadded domain with old passing scan shouldn't be queueable",
			mxs: []string{".example.com"}, scan: withTimestamp(goodScan, time.Now().Add(time.Duration(-1)*time.Hour)),
			err: nil, expected: false},
		{desc: "Domain with passing scan but mismatched hostnames shouldn't be queueable",
			mxs: []string{"mx1.example.com"}, scan: goodScan, err: nil, expected: false},
		{desc: "Domain with failing scan shouldn't be queueable", scan: failedScan, err: nil, expected: false},
		{desc: "Domain without scan shouldn't be queueable", err: errors.New(""), expected: false},
		{desc: "Domain with MTA-STS should be queueable",
			mxs: []string{".example.com"}, scan: goodScan, mtasts: true, expected: true},
		{desc: "Domain with MTA-STS but MTA-STS scan failed shouldn't be queueable",
			mxs: []string{".example.com"}, scan: withBadMTASTS(goodScan), mtasts: true, expected: false},
	}
	for _, tc := range testCases {
		store := mockScanStore{tc.scan, tc.err}
		policy := newP.withMXs(tc.mxs)
		policy.MTASTS = tc.mtasts
		got, msg := (&policy).HasValidScan(store)
		if got != tc.expected {
			t.Errorf("%s: expected %t but got %t: %s", tc.desc, tc.expected, got, msg)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	var testCases = []struct {
		desc         string
		onList       bool
		inDB         bool
		errDB        error
		errPendingDB error
		inPendingDB  bool
		expected     checker.Status
	}{
		{desc: "Domain on the list should return success", onList: true, expected: checker.Success},
		{desc: "Domain not on list but in policies DB should return warning", inDB: true, expected: checker.Warning},
		{desc: "DB error should surface", errDB: errors.New(""), expected: checker.Error},
		{desc: "Pending DB error should surface", errPendingDB: errors.New(""), expected: checker.Error},
		{desc: "Domain in pending policies DB should return failure", inPendingDB: true, expected: checker.Failure},
		{desc: "Domain not anywhere should return failure", expected: checker.Failure},
	}
	for _, tc := range testCases {
		policy := &PolicySubmission{Policy: &policy.TLSPolicy{}}
		result := policy.PolicyListCheck(
			&mockPolicyStore{err: tc.errPendingDB, ok: tc.inPendingDB}, &mockPolicyStore{err: tc.errDB, ok: tc.inDB}, mockList{tc.onList})
		if result.Status != tc.expected {
			t.Errorf("%s: expected status %d, got result %v", tc.desc, tc.expected, result)
		}
	}
}

func TestInitializeWithToken(t *testing.T) {
	mockToken := mockTokenStore{domain: "domain", err: nil}
	domainObj := PolicySubmission{Name: "example.com"}
	_, err := domainObj.InitializeWithToken(&mockPolicyStore{err: errors.New("")}, &mockToken)
	if err == nil {
		t.Error("Expected InitializeWithToken to forward error message from DB")
	}
	if mockToken.token != nil {
		t.Error("Token should not have been set if domain not found")
	}
	_, err = domainObj.InitializeWithToken(&mockPolicyStore{policy: domainObj}, &mockTokenStore{err: errors.New("")})
	if err == nil {
		t.Error("Expected InitializeWithToken to forward error message from DB")
	}
	domainObj.InitializeWithToken(&mockPolicyStore{policy: domainObj, err: nil}, &mockToken)
	if mockToken.token == nil {
		t.Error("Token should have been set for domain")
	}
}
