package models

import (
	"errors"
	"testing"
)

type mockTokenStore struct {
	token  *Token
	domain string
	err    error
}

func (m *mockTokenStore) PutToken(domain string) (Token, error) {
	m.token = &Token{Domain: domain, Token: "token"}
	return *m.token, m.err
}

func (m *mockTokenStore) UseToken(token string) (string, error) {
	return m.domain, m.err
}

func TestRedeemToken(t *testing.T) {
	domains := mockDomainStore{domain: Domain{Name: "anything", State: StateUnvalidated}, err: nil}
	token := Token{Token: "token"}
	domain, userErr, dbErr := token.Redeem(&domains, &mockTokenStore{domain: "anything", err: nil})
	if domain != "anything" || userErr != nil || dbErr != nil {
		t.Error("Expected token redeem to succeed")
	}
	if domains.domain.State != StateTesting {
		t.Error("Expected PutDomain to have upgraded domain State")
	}
}

func TestRedeemTokenFailures(t *testing.T) {
	token := Token{Token: "token"}
	_, userErr, _ := token.Redeem(&mockDomainStore{err: nil}, &mockTokenStore{err: errors.New("")})
	if userErr == nil {
		t.Error("Errors reported from the token store should be interpreted as usage error (token already used, or doesn't exist)")
	}
	_, _, dbErr := token.Redeem(&mockDomainStore{err: errors.New("")}, &mockTokenStore{err: nil})
	if dbErr == nil {
		t.Error("Errors reported from the domain store should be interpreted as a hard failure")
	}
}
