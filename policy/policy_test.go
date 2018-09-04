package policy

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

var mockList = list{
	Policies: map[string]TLSPolicy{
		"eff.org": TLSPolicy{Mode: "testing"},
	},
}

func mockFetchHTTP() (list, error) {
	return mockList, nil
}

func mockErroringFetchHTTP() (list, error) {
	return list{}, fmt.Errorf("something went wrong")
}

func TestGetPolicy(t *testing.T) {
	list := makeUpdatedList(mockFetchHTTP, time.Hour)

	policy, err := list.Get("not-on-the-list.com")
	if err == nil {
		t.Error("Getting the policy for an unlisted domain should return an error")
	}

	policy, err = list.Get("eff.org")
	if err != nil {
		t.Errorf("Unexpected error while getting policy: %s", err)
	}
	if !reflect.DeepEqual(policy, mockList.Policies["eff.org"]) {
		t.Errorf("Expected policy for eff.org to be %v, got %v", mockList.Policies["eff.org"], policy)
	}
}

func TestFailedListUpdate(t *testing.T) {
	list := makeUpdatedList(mockErroringFetchHTTP, time.Hour)
	_, err := list.Get("eff.org")
	if err == nil {
		t.Errorf("Get should return an error if fetching the list fails")
	}
}

func TestListUpdate(t *testing.T) {
	var updatedList = list{Policies: map[string]TLSPolicy{}}
	list := makeUpdatedList(func() (list, error) { return updatedList, nil }, time.Second)
	_, err := list.Get("example.com")
	if err == nil {
		t.Error("Getting the policy for an unlisted domain should return an error")
	}
	// Update the list!
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
	var updatedList = list{Policies: map[string]TLSPolicy{
		"eff.org":     TLSPolicy{},
		"example.com": TLSPolicy{},
	}}
	list := makeUpdatedList(func() (list, error) { return updatedList, nil }, time.Second)
	domains, _ := list.DomainsToValidate()
	if !reflect.DeepEqual([]string{"eff.org", "example.com"}, domains) {
		t.Errorf("Expected eff.org and example.com to be returned")
	}
}

func TestHostnamesForDomain(t *testing.T) {
	hostnames := []string{"a", "b", "c"}
	var updatedList = list{Policies: map[string]TLSPolicy{
		"eff.org": TLSPolicy{MXs: hostnames}}}
	list := makeUpdatedList(func() (list, error) { return updatedList, nil }, time.Second)
	returned, err := list.HostnamesForDomain("eff.org")
	if err != nil {
		t.Fatalf("Encountered %v", err)
	}
	if !reflect.DeepEqual(returned, hostnames) {
		t.Errorf("Expected %s, got %s", hostnames, returned)
	}
}
