package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

func TestUpdateStats(t *testing.T) {
	out = new(bytes.Buffer)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `1,foo,localhost
2,bar,localhost
3,baz,localhost`)
	}))
	defer ts.Close()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"starttls-checker", "--url", ts.URL, "--aggregate=true", "--column=2"}

	// @TODO make this faster
	main()
	got := out.(*bytes.Buffer).String()
	expected, err := json.Marshal(checker.AggregatedScan{
		Time:      time.Time{},
		Source:    ts.URL,
		Attempted: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	timeJSON, err := json.Marshal(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(
		strings.Replace(string(expected), string(timeJSON), ".*", 1),
	)

	if !re.MatchString(got) {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, got)
	}
}
