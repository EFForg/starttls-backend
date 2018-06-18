package policy

import (
	"fmt"
	"reflect"
	"testing"
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
	list := makeUpdatedList(mockFetchHTTP)

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
	list := makeUpdatedList(mockErroringFetchHTTP)
	_, err := list.Get("eff.org")
	if err == nil {
		t.Errorf("Get should return an error if fetching the list fails")
	}
}
