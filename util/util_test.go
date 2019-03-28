package util

import (
	"testing"
)

func TestListsEqual(t *testing.T) {
	testCases := []struct {
		x        []string
		y        []string
		expected bool
	}{
		{[]string{}, []string{}, true},
		{[]string{"a"}, []string{}, false},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a", "a"}, []string{"a"}, false},
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{[]string{"b", "a", "c"}, []string{"a", "b", "c"}, true},
		{[]string{"b", "a", "b", "c"}, []string{"a", "b", "c"}, false},
		{[]string{"b", "a", "b", "c"}, []string{"a", "b", "a", "c"}, false},
		{[]string{"a", "a", "b", "c"}, []string{"a", "b", "a", "c"}, true},
	}
	for _, testCase := range testCases {
		got := ListsEqual(testCase.x, testCase.y)
		if got != testCase.expected {
			t.Errorf("Compared %v and %v, expected %v, got %v", testCase.x, testCase.y, testCase.expected, got)
		}
	}
}
