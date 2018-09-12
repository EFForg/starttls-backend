package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"
)

type mapOrder []string

func (o *mapOrder) UnmarshalJSON(data []byte) error {
	result, err := retrieveKeyOrderingFromMarshaledMap(bytes.NewReader(data))
	*o = result
	return err
}

type listOrder struct {
	PinsetOrder      mapOrder `json:"pinsets"`
	PolicyAliasOrder mapOrder `json:"policy-aliases"`
	PolicyOrder      mapOrder `json:"policies"`
}

// Like a list, but also stores metadata about orderings :)
type orderedList struct {
	list
	listOrder
}

type orderedPinsetMap struct {
	data map[string]Pinset
	mapOrder
}

type orderedPolicyMap struct {
	data map[string]TLSPolicy
	mapOrder
}

func (m orderedPolicyMap) MarshalJSON() ([]byte, error) {
	data := "{"
	for _, key := range m.mapOrder {
		value, err := json.Marshal(m.data[key])
		if err != nil {
			return nil, err
		}
		data += fmt.Sprintf("\"%s\":%s,", key, value)
	}
	return []byte(data[:len(data)-1] + "}"), nil
}

func (m orderedPinsetMap) MarshalJSON() ([]byte, error) {
	data := "{"
	for _, key := range m.mapOrder {
		value, err := json.Marshal(m.data[key])
		if err != nil {
			return nil, err
		}
		data += fmt.Sprintf("\"%s\":%s,", key, value)
	}
	return []byte(data[:len(data)-1] + "}"), nil

}

// MarshalJSON [interface json.Marshaler]
func (l orderedList) MarshalJSON() ([]byte, error) {
	marshalMe := struct {
		Timestamp     time.Time        `json:"timestamp"`
		Expires       time.Time        `json:"expires"`
		Version       string           `json:"version,omitempty"`
		Author        string           `json:"author,omitempty"`
		Pinsets       orderedPinsetMap `json:"pinsets"`
		PolicyAliases orderedPolicyMap `json:"policy-aliases"`
		Policies      orderedPolicyMap `json:"policies"`
	}{
		Timestamp:     l.Timestamp,
		Expires:       l.Expires,
		Version:       l.Version,
		Author:        l.Author,
		Pinsets:       orderedPinsetMap{l.Pinsets, l.PinsetOrder},
		PolicyAliases: orderedPolicyMap{l.PolicyAliases, l.PolicyAliasOrder},
		Policies:      orderedPolicyMap{l.Policies, l.PolicyOrder},
	}
	return json.Marshal(marshalMe)
}

// Retrieves a list of each top-level key found in a marshaled JSON
// represented by an io.Reader stream.
func retrieveKeyOrderingFromMarshaledMap(buffer io.Reader) ([]string, error) {
	keys := []string{}
	// The default JSON decoder iterates through delimeters {} [], and values
	// strings, numbers, and booleans.
	// Note that the ":" code point, which delimits keys and values, is skipped.
	// So we guess that a particular token is a top-level key if:
	//   * the token is not in any nested object
	//   * the previous token was not a key
	dec := json.NewDecoder(buffer)
	level := 0
	previousWasKey := false
	for {
		t, err := dec.Token()
		if err == io.EOF {
			// If level > 0 but we encounter EOF, something's wrong.
			if level != 0 {
				return nil, fmt.Errorf("unexpected EOF while parsing JSON")
			}
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		// If we're at nested level 1, and we encounter a string token, and
		// the previous token was *not* a key, then this is a top-level key.
		switch t.(type) {
		case json.Delim:
			if t == json.Delim('{') {
				level++
			} else if t == json.Delim('}') {
				level--
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
	return keys, nil
}

// UnmarshalJSON [interface json.Unmarshaler]
func (l *orderedList) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &(l.list)); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &(l.listOrder)); err != nil {
		return err
	}
	return nil
}
