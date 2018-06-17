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

// Pinset represents a set of valid public keys for a domain's
// SSL certificate.
type Pinset struct {
	StaticSPKIHashes []string `json:"static-spki-hashes"`
}

// TLSPolicy dictates the policy for a particular email domain.
type TLSPolicy struct {
	PolicyAlias   string   `json:"policy-alias,omitempty"`
	MinTLSVersion string   `json:"min-tls-version,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	MXs           []string `json:"mxs,omitempty"`
	Pin           string   `json:"pin,omitempty"`
	Report        string   `json:"report,omitempty"`
}

// List is a raw representation of the policy list.
type List struct {
	Timestamp     time.Time            `json:"timestamp"`
	Expires       time.Time            `json:"expires"`
	Version       string               `json:"version"`
	Author        string               `json:"author"`
	Pinsets       map[string]Pinset    `json:"pinsets"`
	PolicyAliases map[string]TLSPolicy `json:"policy-aliases"`
	Policies      map[string]TLSPolicy `json:"policies"`
}

func (l *List) Add(domain string, policy TLSPolicy) {
	l.Policies[domain] = policy
}

// get retrieves the TLSPolicy for a domain, and resolves
// aliases if they exist.
func (l List) get(domain string) (TLSPolicy, error) {
	policy, ok := l.Policies[domain]
	if !ok {
		return TLSPolicy{}, fmt.Errorf("Policy for %s doesn't exist", domain)
	}
	if len(policy.PolicyAlias) > 0 {
		policy, ok = l.PolicyAliases[policy.PolicyAlias]
		if !ok {
			return TLSPolicy{}, fmt.Errorf("Policy alias for %s doesn't exist", domain)
		}
	}
	return policy, nil
}

// UpdatedList wraps a list that is updated from a remote
// policyURL every hour. Safe for concurrent calls to `Get`.
type UpdatedList struct {
	mu sync.RWMutex
	List
}

// Get safely reads from the underlying policy list and returns a TLSPolicy for a domain
func (l UpdatedList) Get(domain string) (TLSPolicy, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.get(domain)
}

// fetchListFn returns a new policy list. It can be used to update UpdatedList
type fetchListFn func() (List, error)

// Retrieve and parse List from policyURL
func FetchListHTTP() (List, error) {
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
		l.List = newList
		l.mu.Unlock()
	}
}

// makeUpdatedList constructs an UpdatedList object and launches a
// thread to continually update it. Accepts a fetchListFn to allow
// stubbing http request to remote policy list.
func makeUpdatedList(fetch fetchListFn, updateFrequency time.Duration) UpdatedList {
	l := UpdatedList{}
	l.update(fetch)

	go func() {
		for {
			l.update(fetch)
			time.Sleep(updateFrequency)
		}
	}()
	return l
}

// MakeUpdatedList wraps makeUpdatedList to use FetchListHTTP by default to update policy list
func MakeUpdatedList() UpdatedList {
	return makeUpdatedList(FetchListHTTP, time.Hour)
}
