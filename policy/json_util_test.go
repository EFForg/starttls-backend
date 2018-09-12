package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestRetrieveKeyOrdering(t *testing.T) {
	data := "{\"hi\": \"dumb\", \"lol\": 4, \"am\": {\"b\":{}, \"c\":3}, \"xx\":\"hi\", \"xxx\": \"lol\"}\n"
	result, _ := retrieveKeyOrderingFromMarshaledMap(strings.NewReader(data))
	expected := []string{"hi", "lol", "am", "xx", "xxx"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %s, not %s", expected, result)
	}
}

func TestRetrieveSingleKeyOrdering(t *testing.T) {
	data := "{\"lol\":{}}\n"
	result, _ := retrieveKeyOrderingFromMarshaledMap(strings.NewReader(data))
	expected := []string{"lol"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %s, not %s", expected, result)
	}
}

func TestRetrieveKeyOrderingEmpty(t *testing.T) {
	data := "{}\n"
	result, _ := retrieveKeyOrderingFromMarshaledMap(strings.NewReader(data))
	expected := []string{}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %s, not %s", expected, result)
	}
}

func TestRetrieveKeyOrderingErrors(t *testing.T) {
	// Unmatched brace should lead to an error
	data := "{\"lol\":{}"
	_, err := retrieveKeyOrderingFromMarshaledMap(strings.NewReader(data))
	if err == nil {
		t.Errorf("Expected error while parsing JSON")
	}
}

func TestUnmarshalOrderedList(t *testing.T) {
	l := orderedList{}
	data := []byte("{\"a\":2, \"pinsets\": {\"x\":{}, \"a\":{}}, \"policies\":{\"c\":{},\"b\":{},\"a\":{}}, \"b\":3}")
	err := json.Unmarshal(data, &l)
	if err != nil {
		t.Fatalf("%v", err)
	}
	expected := mapOrder([]string{"x", "a"})
	if !reflect.DeepEqual(l.PinsetOrder, expected) {
		t.Errorf("Expected %s, not %s", expected, l.PinsetOrder)
	}
	expected = []string{"c", "b", "a"}
	if !reflect.DeepEqual(l.PolicyOrder, expected) {
		t.Errorf("Expected %s, not %s", expected, l.PolicyOrder)
	}
}

func TestUnmarshalOrderedListLong(t *testing.T) {
	l := orderedList{}
	err := json.Unmarshal([]byte(testPolicyJSON), &l)
	if err != nil {
		t.Fatalf("%v", err)
	}
	expected := mapOrder([]string{"example-c", "example-b", "example-a"})
	if !reflect.DeepEqual(l.PinsetOrder, expected) {
		t.Errorf("Expected %s, not %s", expected, l.PinsetOrder)
	}
	expected = []string{"example.com", "eff.org"}
	if !reflect.DeepEqual(l.PolicyOrder, expected) {
		t.Errorf("Expected %s, not %s", expected, l.PolicyOrder)
	}
}

func TestMarshalPreservesOrdering(t *testing.T) {
	l := orderedList{}
	err := json.Unmarshal([]byte(testPolicyJSON), &l)
	if err != nil {
		t.Fatalf("%v", err)
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if strings.Compare(string(data), testPolicyJSON) != 0 {
		t.Errorf("should have marshalled back to the same")
	}
}

const testPolicyJSON = `{
  "timestamp": "2018-09-07T10:46:28.284618421-07:00",
  "expires": "2018-09-21T10:46:28.284618421-07:00",
  "pinsets": {
    "example-c": {},
    "example-b": {},
    "example-a": {}
  },
  "policy-aliases": {
    "eff": {
      "mode": "testing",
      "mxs": [
        ".eff.org"
      ]
    },
    "example": {
      "mode": "testing",
      "mxs": [
        ".example.com"
      ]
    }
  },
  "policies": {
    "example.com": {
      "policy-alias": "example"
    },
    "eff.org": {
      "policy-alias": "eff"
    }
  }
}`
