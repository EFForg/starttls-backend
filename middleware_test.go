package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPanicRecovery(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Expected server to handle panic")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/panic", panickingHandler)
	panicServer := httptest.NewServer(registerHandlers(api, mux))
	defer panicServer.Close()

	resp, err := http.Get(fmt.Sprintf("%s/panic", panicServer.URL))

	if err != nil {
		t.Errorf("Request to panic endpoint failed: %s\n", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected server to respond with 500, got %d", resp.StatusCode)
	}
}

func panickingHandler(w http.ResponseWriter, r *http.Request) {
	panic(fmt.Errorf("oh no"))
}

func TestAllowedOrigins(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "foo.example.com,bar.example.com")
	server := httptest.NewServer(registerHandlers(api, http.NewServeMux()))
	defer server.Close()

	// Allowed domain should get CORS header
	req, err := http.NewRequest("GET", server.URL+"/api/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("origin", "foo.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	corsHeader := resp.Header["Access-Control-Allow-Origin"]
	if len(corsHeader) != 1 || corsHeader[0] != "foo.example.com" {
		t.Error("Expected CORS header to be set for allowed domain")
	}

	// Disallowed domain should not get CORS header
	req, err = http.NewRequest("GET", server.URL+"/api/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("origin", "baz.example.com")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header["Access-Control-Allow-Origin"] != nil {
		t.Error("Expected CORS header to be set for allowed domain")
	}
}
