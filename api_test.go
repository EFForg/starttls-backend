package main

import (
	"testing"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
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

	domain := models.Domain{
		Name:  "example.com",
		Email: "postmaster@example.com",
		State: models.StateUnvalidated,
	}
	api.Database.PutDomain(domain)
	result := api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
	}
	domain.State = models.StateQueued
	api.Database.PutDomain(domain)
	result = api.policyCheck("example.com")
	if result.Status != checker.Warning {
		t.Errorf("Check should have warned.")
	}
}
