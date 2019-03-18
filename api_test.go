package main

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func testHTMLPost(path string, data url.Values, t *testing.T) ([]byte, int) {
	req, err := http.NewRequest("POST", server.URL+path, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "text/html")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if !strings.Contains(strings.ToLower(string(body)), "</html") {
		t.Errorf("Response should be HTML, got %s", string(body))
	}
	return body, resp.StatusCode
}
