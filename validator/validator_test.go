package validator

import (
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

type mockDomainPolicyStore struct {
	hostnames map[string][]string
}

func (m mockDomainPolicyStore) DomainsToValidate() ([]string, error) {
	domains := []string{}
	for domain := range m.hostnames {
		domains = append(domains, domain)
	}
	return domains, nil
}

func (m mockDomainPolicyStore) HostnamesForDomain(domain string) ([]string, error) {
	return m.hostnames[domain], nil
}

func noop(_ string, _ string, _ checker.DomainResult) {}

func TestRegularValidationValidates(t *testing.T) {
	called := make(chan bool)
	fakeChecker := func(domain string, hostnames []string) checker.DomainResult {
		called <- true
		return checker.DomainResult{}
	}
	mock := mockDomainPolicyStore{
		hostnames: map[string][]string{"a": []string{"hostname"}}}
	v := Validator{Store: mock, Interval: 100 * time.Millisecond, checkPerformer: fakeChecker, OnFailure: noop}
	go v.Run()

	select {
	case <-called:
		return
	case <-time.After(time.Second):
		t.Errorf("Checker wasn't called on hostname!")
	}
}

func TestRegularValidationReportsErrors(t *testing.T) {
	reports := make(chan string)
	fakeChecker := func(domain string, hostnames []string) checker.DomainResult {
		if domain == "fail" || domain == "error" {
			return checker.DomainResult{Status: 5}
		}
		return checker.DomainResult{Status: 0}
	}
	fakeReporter := func(name string, domain string, result checker.DomainResult) {
		reports <- domain
	}
	successReports := make(chan string)
	fakeSuccessReporter := func(name string, domain string, result checker.DomainResult) {
		successReports <- domain
	}
	mock := mockDomainPolicyStore{
		hostnames: map[string][]string{
			"fail":   []string{"hostname"},
			"error":  []string{"hostname"},
			"normal": []string{"hostname"}}}
	v := Validator{Store: mock, Interval: 100 * time.Millisecond, checkPerformer: fakeChecker,
		OnFailure: fakeReporter, OnSuccess: fakeSuccessReporter,
	}
	go v.Run()
	recvd := make(map[string]bool)
	numRecvd := 0
	for numRecvd < 4 {
		select {
		case report := <-successReports:
			if report != "normal" {
				t.Errorf("Didn't expect %s to succeed", report)
			}
		case report := <-reports:
			recvd[report] = true
			numRecvd++
		case <-time.After(time.Second):
			t.Errorf("Timed out waiting for reports")
		}
	}
	if _, ok := recvd["fail"]; !ok {
		t.Errorf("Expected fail to be reported")
	}
	if _, ok := recvd["error"]; !ok {
		t.Errorf("Expected error to be reported")
	}
	if _, ok := recvd["normal"]; ok {
		t.Errorf("Didn't expect normal to be reported as failure")
	}
}
