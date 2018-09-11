package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"
)

type MapOrder []string

func (o *MapOrder) UnmarshalJSON(data []byte) error {
	*o = retrieveKeyOrderingFromMarshaledMap(bytes.NewReader(data))
	return nil
}

type listOrder struct {
	PinsetOrder      MapOrder `json:"pinsets"`
	PolicyAliasOrder MapOrder `json:"policy-aliases"`
	PolicyOrder      MapOrder `json:"policies"`
}

// Like a list, but also stores metadata about orderings :)
type OrderedList struct {
	list
	listOrder
}

type OrderedPinsetMap struct {
	data map[string]Pinset
	MapOrder
}

type OrderedPolicyMap struct {
	data map[string]TLSPolicy
	MapOrder
}

func (m OrderedPolicyMap) MarshalJSON() ([]byte, error) {
	data := "{"
	for _, key := range m.MapOrder {
		value, err := json.Marshal(m.data[key])
		if err != nil {
			return nil, err
		}
		data += fmt.Sprintf("\"%s\":%s,", key, value)
	}
	return []byte(data[:len(data)-1] + "}"), nil
}

func (m OrderedPinsetMap) MarshalJSON() ([]byte, error) {
	data := "{"
	for _, key := range m.MapOrder {
		value, err := json.Marshal(m.data[key])
		if err != nil {
			return nil, err
		}
		data += fmt.Sprintf("\"%s\":%s,", key, value)
	}
	return []byte(data[:len(data)-1] + "}"), nil

}

// MarshalJSON [interface json.Marshaler]
func (l OrderedList) MarshalJSON() ([]byte, error) {
	marshalMe := struct {
		Timestamp     time.Time        `json:"timestamp"`
		Expires       time.Time        `json:"expires"`
		Version       string           `json:"version,omitempty"`
		Author        string           `json:"author,omitempty"`
		Pinsets       OrderedPinsetMap `json:"pinsets"`
		PolicyAliases OrderedPolicyMap `json:"policy-aliases"`
		Policies      OrderedPolicyMap `json:"policies"`
	}{
		Timestamp:     l.Timestamp,
		Expires:       l.Expires,
		Version:       l.Version,
		Author:        l.Author,
		Pinsets:       OrderedPinsetMap{l.Pinsets, l.PinsetOrder},
		PolicyAliases: OrderedPolicyMap{l.PolicyAliases, l.PolicyAliasOrder},
		Policies:      OrderedPolicyMap{l.Policies, l.PolicyOrder},
	}
	return json.Marshal(marshalMe)
}

// Performs an action on each top-level key found in a marshaled JSON
// represented by an io.Reader.
// The callback is passed 1) the key itself, and 2) an io.Reader which starts
// at the associated value, just past the colon separating the two.
func retrieveKeyOrderingFromMarshaledMap(buffer io.Reader) []string {
	keys := []string{}
	dec := json.NewDecoder(buffer)
	level := 0
	previousWasKey := false
	for {
		t, err := dec.Token()
		if err == io.EOF {
			if level != 0 {
				log.Fatalf("unexpected EOF at nesting level %d", level)
			}
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		// If we're at nested level 1, and we encounter a string token, and
		// the previous token was *not* a key, we can safely assume that
		// this token is a key.
		// TODO: Is there a JSON grammar/parsing spec we can cite to prove this?
		switch t.(type) {
		case json.Delim:
			if t == json.Delim('{') {
				level += 1
			} else if t == json.Delim('}') {
				level -= 1
			}
		case string:
			if level == 1 && !previousWasKey {
				keys = append(keys, t.(string))
				previousWasKey = true
				continue
			}
		}
		previousWasKey = false
		if level <= 0 { // If we hit level 0 again, stop.
			break
		}
	}
	return keys
}

// UnmarshalJSON [interface json.Unmarshaler]
func (l *OrderedList) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &(l.list)); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &(l.listOrder)); err != nil {
		return err
	}
	return nil
}
