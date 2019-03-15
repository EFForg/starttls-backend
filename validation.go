package main

import (
	"fmt"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/validator"

	"github.com/getsentry/raven-go"
)

// Called with failure by default, or if any of the validation side-effects fail.
func reportToSentry(name string, domain string, message string, result checker.DomainResult) {
	raven.CaptureMessageAndWait("Validation failed for previously validated domain",
		map[string]string{
			"validatorName": name,
			"domain":        result.Domain,
			"status":        fmt.Sprintf("%d", result.Status),
		},
		result)
}

type testingValidator struct {
	validator.Validator
	store   models.DomainStore
	emailer EmailSender
}

func (t *testingValidator) domainFails(name string, domain string, result checker.DomainResult) {
	domainInfo, err := t.store.GetDomain(domain)
	if err != nil {
		reportToSentry(name, domain,
			fmt.Sprintf("Error when retrieving information for %s failed validation: %v",
				domain, err), result)
		return
	}
	t.store.SetStatus(domain, models.StateFailed)
	err = t.emailer.SendFailure(&domainInfo, result.Message)
	if err != nil {
		reportToSentry(name, domain, fmt.Sprintf("Error sending failure email: %v", err), result)
	} else {
		reportToSentry(name, domain, "Validation failed for queued domain", result)
	}
}

func (t *testingValidator) domainPasses(name string, domain string, result checker.DomainResult) {
	domainInfo, err := t.store.GetDomain(domain)
	if err != nil {
		reportToSentry(name, domain,
			fmt.Sprintf("Error when retrieving information for %s successful validation: %v",
				domain, err), result)
	}
	if domainInfo.TestingPeriodFinished() {
		t.store.SetStatus(domain, models.StateEnforce)
	}
	err = t.emailer.SendSuccess(&domainInfo)
	if err != nil {
		reportToSentry(name, domain, fmt.Sprintf("Error sending failure email: %v", err), result)
	}
}

func validateTestingDomains(store models.DomainStore, policyStore validator.DomainPolicyStore, emailer EmailSender) {
	v := testingValidator{
		store:   store,
		emailer: emailer,
		Validator: validator.Validator{
			Name:     "Testing domains",
			Store:    policyStore,
			Interval: 24 * time.Hour,
		},
	}
	v.OnSuccess = v.domainPasses
	v.OnFailure = v.domainFails
	go v.Run()
}
