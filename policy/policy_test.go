package policy

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

var mockList = List{
	Policies: map[string]TLSPolicy{
		"eff.org": TLSPolicy{Mode: "testing"},
	},
}

func mockFetchHTTP() (List, error) {
	return mockList, nil
}

func mockErroringFetchHTTP() (List, error) {
	return List{}, fmt.Errorf("something went wrong")
}

func TestGetPolicy(t *testing.T) {
	list := makeUpdatedList(mockFetchHTTP, time.Hour)

	policy, err := list.Get("not-on-the-List.com")
	if err == nil {
		t.Error("Getting the policy for an unListed domain should return an error")
	}

	policy, err = list.Get("eff.org")
	if err != nil {
		t.Errorf("Unexpected error while getting policy: %s", err)
	}
	if !reflect.DeepEqual(policy, mockList.Policies["eff.org"]) {
		t.Errorf("Expected policy for eff.org to be %v, got %v", mockList.Policies["eff.org"], policy)
	}
}

func TestHasDomain(t *testing.T) {
	list := makeUpdatedList(mockFetchHTTP, time.Hour)

	if list.HasDomain("not-on-the-List.com") {
		t.Error("Calling HasDomain for an unListed domain should return false")
	}

	if !list.HasDomain("eff.org") {
		t.Error("Calling HasDomain for a Listed domain should return true")
	}
}

func TestFailedListUpdate(t *testing.T) {
	list := makeUpdatedList(mockErroringFetchHTTP, time.Hour)
	_, err := list.Get("eff.org")
	if err == nil {
		t.Errorf("Get should return an error if fetching the List fails")
	}
}

func TestListUpdate(t *testing.T) {
	var updatedList = List{Policies: map[string]TLSPolicy{}}
	list := makeUpdatedList(func() (List, error) { return updatedList, nil }, time.Second)
	_, err := list.Get("example.com")
	if err == nil {
		t.Error("Getting the policy for an unListed domain should return an error")
	}
	// Update the List!
	updatedList.Policies["example.com"] = TLSPolicy{Mode: "testing"}
	time.Sleep(time.Second * 2)
	policy, err := list.Get("example.com")
	if err != nil {
		t.Errorf("Unexpected error while getting policy: %s", err)
	}
	if !reflect.DeepEqual(policy, updatedList.Policies["example.com"]) {
		t.Errorf("Expected policy for example.com to be %v, got %v", mockList.Policies["eff.org"], policy)
	}
}

func TestDomainsToValidate(t *testing.T) {
	var updatedList = List{Policies: map[string]TLSPolicy{
		"eff.org":     TLSPolicy{},
		"example.com": TLSPolicy{},
	}}
	list := makeUpdatedList(func() (List, error) { return updatedList, nil }, time.Second)
	domains, err := list.DomainsToValidate()
	if err != nil {
		t.Fatalf("Encoutnered %v", err)
	}
	if len(updatedList.Policies) != len(domains) {
		t.Fatalf("Expected domains to validate to match policy list, got %s", domains)
	}
	for _, domain := range domains {
		if _, exists := updatedList.Policies[domain]; !exists {
			t.Fatalf("Expected domains to validate to match policy list, got %s", domains)
		}
	}
}

func TestHostnamesForDomain(t *testing.T) {
	hostnames := []string{"a", "b", "c"}
	var updatedList = List{Policies: map[string]TLSPolicy{
		"eff.org": TLSPolicy{MXs: hostnames}}}
	list := makeUpdatedList(func() (List, error) { return updatedList, nil }, time.Second)
	returned, err := list.HostnamesForDomain("eff.org")
	if err != nil {
		t.Fatalf("Encountered %v", err)
	}
	if !reflect.DeepEqual(returned, hostnames) {
		t.Errorf("Expected %s, got %s", hostnames, returned)
	}
}

func TestCloneDoesntChangeOriginal(t *testing.T) {
	var updatedList = List{
		Version: "3",
		Policies: map[string]TLSPolicy{
			"eff.org": TLSPolicy{MXs: []string{"a"}}}}
	list := makeUpdatedList(func() (List, error) { return updatedList, nil }, time.Hour)
	newList := list.Raw()
	// Change new list
	newList.Version = "5"
	effPolicy := newList.Policies["eff.org"]
	effPolicy.MXs = []string{"a", "b"}
	list.mu.RLock()
	defer list.mu.RUnlock()
	if list.Version == "5" || len(list.Policies["eff.org"].MXs) > 1 {
		t.Errorf("Expected original to remain unchanged after changing copy")
	}
}
