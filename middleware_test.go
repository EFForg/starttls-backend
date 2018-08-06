package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
