package main

import (
	"testing"

	"github.com/EFForg/starttls-check/checker"
	"github.com/EFForg/starttls-scanner/db"
)

func TestPolicyCheck(t *testing.T) {
	defer teardown()

	result := api.policyCheck("eff.org")
	if result.Status != checker.Success {
		t.Errorf("Check should have succeeded.")
	}
	result = api.policyCheck("failmail.com")
	if result.Status != checker.Failure {
		t.Errorf("Check should have failed.")
	}
}

func TestPolicyCheckWithQueuedDomain(t *testing.T) {
	defer teardown()

	domainData := db.DomainData{
		Name:  "example.com",
		Email: "postmaster@example.com",
		State: db.StateUnvalidated,
	}
	api.Database.PutDomain(domainData)
	result := api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
	}
	domainData.State = db.StateQueued
	api.Database.PutDomain(domainData)
	result = api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
	}
}
