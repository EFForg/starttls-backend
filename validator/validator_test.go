package validator

import (
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
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

func (m mockDomainPolicyStore) GetDomainPolicy(domain string) (models.Domain, error) {
	return models.Domain{Name: domain, MXs: m.hostnames[domain]}, nil
}

func noop(_ string, _ models.Domain, _ checker.DomainResult) {}

func TestRegularValidationValidates(t *testing.T) {
	called := make(chan bool)
	fakeChecker := func(_ models.Domain) checker.DomainResult {
		called <- true
		return checker.DomainResult{}
	}
	mock := mockDomainPolicyStore{
		hostnames: map[string][]string{"a": []string{"hostname"}}}
	v := Validator{Store: mock, Interval: 100 * time.Millisecond, CheckPerformer: fakeChecker, OnFailure: noop}
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
	fakeChecker := func(domain models.Domain) checker.DomainResult {
		if domain.Name == "fail" || domain.Name == "error" {
			return checker.DomainResult{Status: 5}
		}
		return checker.DomainResult{Status: 0}
	}
	fakeReporter := func(name string, domain models.Domain, result checker.DomainResult) {
		reports <- domain.Name
	}
	successReports := make(chan string)
	fakeSuccessReporter := func(name string, domain models.Domain, result checker.DomainResult) {
		successReports <- domain.Name
	}
	mock := mockDomainPolicyStore{
		hostnames: map[string][]string{
			"fail":   []string{"hostname"},
			"error":  []string{"hostname"},
			"normal": []string{"hostname"}}}
	v := Validator{Store: mock, Interval: 100 * time.Millisecond, CheckPerformer: fakeChecker,
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
