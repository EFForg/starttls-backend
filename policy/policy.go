package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

// policyURL is the default URL from which to fetch the policy JSON.
const policyURL = "https://dl.eff.org/starttls-everywhere/policy.json"

// TLSPolicy dictates the policy for a particular email domain.
type TLSPolicy struct {
	PolicyAlias string `json:"policy-alias,omitempty"`
	// Mode corresponds with MTA-STS modes: can be one of
	// `enforce`, `testing`, or `none`.
	Mode string   `json:"mode,omitempty"`
	MXs  []string `json:"mxs,omitempty"`
}

// List is a raw representation of the policy list.
type List struct {
	Timestamp     time.Time            `json:"timestamp"`
	Expires       time.Time            `json:"expires"`
	Version       string               `json:"version"`
	Author        string               `json:"author"`
	PolicyAliases map[string]TLSPolicy `json:"policy-aliases"`
	Policies      map[string]TLSPolicy `json:"policies"`
}

// Equals tests equality between this policy and another.
func (p *TLSPolicy) Equals(other *TLSPolicy) bool {
	if other == nil {
		return false
	}
	return p.Mode == other.Mode && p.hostnamesEqual(other)
}

// Assumption: Every string is unique in the MXs list.
func (p *TLSPolicy) hostnamesEqual(other *TLSPolicy) bool {
	if len(p.MXs) != len(other.MXs) {
		return false
	}
	set := make(map[string]bool)
	for _, mx := range p.MXs {
		set[mx] = true
	}
	for _, mx := range other.MXs {
		if !set[mx] {
			return false
		}
	}
	return true
}

// Add adds a particular domain's policy to the list.
func (l *List) Add(domain string, policy TLSPolicy) {
	l.Policies[domain] = policy
}

// get retrieves the TLSPolicy for a domain, and resolves
// aliases if they exist.
func (l *List) get(domain string) (TLSPolicy, error) {
	policy, ok := l.Policies[domain]
	if !ok {
		return TLSPolicy{}, fmt.Errorf("policy for domain %s doesn't exist", domain)
	}
	if len(policy.PolicyAlias) > 0 {
		policy, ok = l.PolicyAliases[policy.PolicyAlias]
		if !ok {
			return TLSPolicy{}, fmt.Errorf("policy alias for domain %s doesn't exist", domain)
		}
	}
	return policy, nil
}

// UpdatedList wraps a list that is updated from a remote
// policyURL every hour. Safe for concurrent calls to `Get`.
type UpdatedList struct {
	mu sync.RWMutex
	*List
}

// DomainsToValidate [interface Validator] retrieves domains from the
// DB whose policies should be validated.
func (l *UpdatedList) DomainsToValidate() ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	domains := []string{}
	for domain := range l.Policies {
		domains = append(domains, domain)
	}
	return domains, nil
}

// HostnamesForDomain [interface Validator] retrieves the hostname policy for
// a particular domain.
func (l *UpdatedList) HostnamesForDomain(domain string) ([]string, error) {
	policy, err := l.Get(domain)
	if err != nil {
		return []string{}, err
	}
	return policy.MXs, nil
}

// Get safely reads from the underlying policy list and returns a TLSPolicy for a domain
func (l *UpdatedList) Get(domain string) (TLSPolicy, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.get(domain)
}

// HasDomain returns true if a domain is present on the policy list.
func (l *UpdatedList) HasDomain(domain string) bool {
	_, err := l.Get(domain)
	return err == nil
}

// Raw returns a raw List struct, copied from the underlying one
func (l *UpdatedList) Raw() List {
	l.mu.RLock()
	defer l.mu.RUnlock()
	list := *l.List
	list.Timestamp = l.Timestamp
	list.Expires = l.Expires
	list.PolicyAliases = make(map[string]TLSPolicy)
	for alias, policy := range l.PolicyAliases {
		list.PolicyAliases[alias] = policy.clone()
	}
	list.Policies = make(map[string]TLSPolicy)
	for domain, policy := range l.Policies {
		list.Policies[domain] = policy.clone()
	}
	return list
}

func (p TLSPolicy) clone() TLSPolicy {
	policy := p
	policy.MXs = make([]string, 0)
	for _, mx := range p.MXs {
		policy.MXs = append(policy.MXs, mx)
	}
	return policy
}

// fetchListFn returns a new policy list. It can be used to update UpdatedList
type fetchListFn func() (List, error)

// Retrieve and parse List from policyURL
func fetchListHTTP() (List, error) {
	resp, err := http.Get(policyURL)
	if err != nil {
		return List{}, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	var policyList List
	err = json.Unmarshal(body, &policyList)
	if err != nil {
		return List{}, err
	}
	return policyList, nil
}

// Get a new policy list and safely assign it the UpdatedList
func (l *UpdatedList) update(fetch fetchListFn) {
	newList, err := fetch()
	if err != nil {
		log.Printf("Error updating policy list: %s\n", err)
	} else {
		l.mu.Lock()
		l.List = &newList
		l.mu.Unlock()
	}
}

// makeUpdatedList constructs an UpdatedList object and launches a
// thread to continually update it. Accepts a fetchListFn to allow
// stubbing http request to remote policy list.
func makeUpdatedList(fetch fetchListFn, updateFrequency time.Duration) *UpdatedList {
	l := UpdatedList{List: &List{}}
	l.update(fetch)

	go func() {
		for {
			l.update(fetch)
			time.Sleep(updateFrequency)
		}
	}()
	return &l
}

// MakeUpdatedList wraps makeUpdatedList to use FetchListHTTP by default to update policy list
func MakeUpdatedList() *UpdatedList {
	return makeUpdatedList(fetchListHTTP, time.Hour)
}
