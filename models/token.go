package models

import "time"

// Token stores the state of an email verification token.
type Token struct {
	Domain  string    `json:"domain"`  // Domain for which we're verifying the e-mail.
	Token   string    `json:"token"`   // Token that we're expecting.
	Expires time.Time `json:"expires"` // When this token expires.
	Used    bool      `json:"used"`    // Whether this token was used.
}

// tokenStore is the interface for performing actions with tokens.
type tokenStore interface {
	PutToken(string) (Token, error)
	UseToken(string) (string, error)
}

// Redeem redeems this Token, and updates its entry in the associated domain and token
// database stores. Returns the domain name that this token was generated for.
func (t *Token) Redeem(pending policyStore, store policyStore, tokens tokenStore) (ret string, userErr error, dbErr error) {
	domain, err := tokens.UseToken(t.Token)
	if err != nil {
		return domain, err, nil
	}
	domainData, ok, err := pending.GetPolicy(domain)
	if !ok || err != nil {
		return domain, nil, err
	}
	err = domainData.moveSubmission(pending, store)
	return domain, nil, err
}
