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
	List := makeUpdatedList(mockFetchHTTP, time.Hour)

	policy, err := List.Get("not-on-the-List.com")
	if err == nil {
		t.Error("Getting the policy for an unListed domain should return an error")
	}

	policy, err = List.Get("eff.org")
	if err != nil {
		t.Errorf("Unexpected error while getting policy: %s", err)
	}
	if !reflect.DeepEqual(policy, mockList.Policies["eff.org"]) {
		t.Errorf("Expected policy for eff.org to be %v, got %v", mockList.Policies["eff.org"], policy)
	}
}

func TestFailedListUpdate(t *testing.T) {
	List := makeUpdatedList(mockErroringFetchHTTP, time.Hour)
	_, err := List.Get("eff.org")
	if err == nil {
		t.Errorf("Get should return an error if fetching the List fails")
	}
}

func TestListUpdate(t *testing.T) {
	var updatedList = List{Policies: map[string]TLSPolicy{}}
	List := makeUpdatedList(func() (List, error) { return updatedList, nil }, time.Second)
	_, err := List.Get("example.com")
	if err == nil {
		t.Error("Getting the policy for an unListed domain should return an error")
	}
	// Update the List!
	updatedList.Policies["example.com"] = TLSPolicy{Mode: "testing"}
	time.Sleep(time.Second * 2)
	policy, err := List.Get("example.com")
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
	List := makeUpdatedList(func() (List, error) { return updatedList, nil }, time.Second)
	domains, _ := List.DomainsToValidate()
	if !reflect.DeepEqual([]string{"eff.org", "example.com"}, domains) {
		t.Errorf("Expected eff.org and example.com to be returned")
	}
}

func TestHostnamesForDomain(t *testing.T) {
	hostnames := []string{"a", "b", "c"}
	var updatedList = List{Policies: map[string]TLSPolicy{
		"eff.org": TLSPolicy{MXs: hostnames}}}
	List := makeUpdatedList(func() (List, error) { return updatedList, nil }, time.Second)
	returned, err := List.HostnamesForDomain("eff.org")
	if err != nil {
		t.Fatalf("Encountered %v", err)
	}
	if !reflect.DeepEqual(returned, hostnames) {
		t.Errorf("Expected %s, got %s", hostnames, returned)
	}
}
