package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// PolicyURL is the default URL from which to fetch the policy JSON.
const PolicyURL = "https://dl.eff.org/starttls-everywhere/policy.json"

// Pinset represents a set of valid public keys for a domain's
// SSL certificate.
type Pinset struct {
	StaticSPKIHashes []string `json:"static-spki-hashes"`
}

// TLSPolicy dictates the policy for a particular email domain.
type TLSPolicy struct {
	PolicyAlias   string   `json:"policy-alias,omitempty"`
	MinTLSVersion string   `json:"min-tls-version,omitempty"`
	Mode          string   `json:"mode"`
	MXs           []string `json:"mxs"`
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

// Get retrieves the TLSPolicy for a domain, and resolves
// aliases if they exist.
func (t List) Get(domain string) (TLSPolicy, error) {
	policy, ok := t.Policies[domain]
	if !ok {
		return TLSPolicy{}, fmt.Errorf("Policy for %d doesn't exist")
	}
	if len(policy.PolicyAlias) > 0 {
		policy, ok = t.PolicyAliases[policy.PolicyAlias]
		if !ok {
			return TLSPolicy{}, fmt.Errorf("Policy alias for %d doesn't exist")
		}
	}
	return policy, nil
}

type listFetcher func(string) (List, error)

// UpdatedList wraps a List that is updated from a remote
// policyURL every hour. Safe for concurrent calls to `Get`.
type UpdatedList struct {
	messages        chan policyRequest
	updateFrequency time.Duration
	fetch           listFetcher
	policyURL       string
}

// Retrieve and parse List from policyURL.
func fetchListHTTP(policyURL string) (List, error) {
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

// A request made to the worker thread.
type policyRequest struct {
	domain    string
	responses chan TLSPolicy
	errors    chan error
}

// This routine serializes all reads and writes to the policy list.
func (l UpdatedList) worker() {
	currentList, err := l.fetch(l.policyURL)
	for true {
		select {
		case req := <-l.messages:
			if err != nil {
				req.errors <- err
				continue
			}
			policy, err := currentList.Get(req.domain)
			if err != nil {
				req.errors <- err
				continue
			}
			req.responses <- policy
		case <-time.After(l.updateFrequency):
			currentList, err = l.fetch(l.policyURL)
		}
	}
}

// Get safely retrieves a domain from the list. This will
// wait for any outstanding writes to be performed before
// reading.
func (l UpdatedList) Get(domain string) (TLSPolicy, error) {
	req := policyRequest{
		domain:    domain,
		responses: make(chan TLSPolicy),
		errors:    make(chan error),
	}
	l.messages <- req
	select {
	case resp := <-req.responses:
		return resp, nil
	case err := <-req.errors:
		return TLSPolicy{}, err
	case <-time.After(time.Second * 3):
		return TLSPolicy{}, fmt.Errorf("Timed out")
	}
}

// CreateUpdatedList constructs and UpdatedList object and launches a
// worker thread to continually update it.
func CreateUpdatedList() UpdatedList {
	list := UpdatedList{
		messages:        make(chan policyRequest),
		policyURL:       PolicyURL,
		fetch:           fetchListHTTP,
		updateFrequency: time.Hour,
	}
	go list.worker()
	return list
}
