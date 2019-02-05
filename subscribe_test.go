package main

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

func testSubscribePost(t *testing.T, domain string, email string, expectedStatus int) url.Values {
	subURL := server.URL + "/api/subscribe"
	data := url.Values{}
	data.Set("domain", domain)
	data.Set("email", email)
	resp, _ := http.PostForm(subURL, data)
	if resp.StatusCode != expectedStatus {
		respText, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("Expected status code %d, got %d: %s",
			expectedStatus, resp.StatusCode, string(respText))
	}
	return data
}

func testConfirmAllSubscriptions(t *testing.T, domain string) {
	subs, err := api.Database.GetSubscriptions()
	if err != nil {
		t.Fatalf("GetSubscriptions failed: %v", err)
	}
	for _, sub := range subs {
		if sub.Confirmed || sub.Domain != domain {
			continue
		}
		token := sub.Token
		tokenData := url.Values{}
		tokenData.Set("token", token)
		resp, _ := http.PostForm(server.URL+"/api/subscribe/confirm", tokenData)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST to api/subscribe failed with error %d", resp.StatusCode)
		}
	}
	subs, _ = api.Database.GetSubscriptions()
	for _, sub := range subs {
		if sub.Domain == domain && !sub.Confirmed {
			t.Fatalf("Subscription should be confirmed")
		}
	}

}

func TestSubscribeExpiredToken(t *testing.T) {

}

func TestDuplicateSubscribes(t *testing.T) {
	testSubscribePost(t, "eff.org", "sydney@eff.org", http.StatusOK)
	// Can re-sub unconfirmed to reset token
	testSubscribePost(t, "eff.org", "sydney@eff.org", http.StatusOK)
	testConfirmAllSubscriptions(t, "eff.org")

	// Can't re-sub same confirmed email/domain pair again!
	testSubscribePost(t, "eff.org", "sydney@eff.org", http.StatusBadRequest)
	// Can if it's different domain or email.
	testSubscribePost(t, "eff.org", "admin@eff.org", http.StatusOK)
	testSubscribePost(t, "sydli.me", "sydney@eff.org", http.StatusOK)
}

// Tests basic subscription workflow.
func TestBasicSubscribe(t *testing.T) {
	defer teardown()

	subURL := server.URL + "/api/subscribe"
	// 1. Subscribe
	values := testSubscribePost(t, "example.com", "me@example.com", http.StatusOK)

	// 2. Confirm Subscription
	testConfirmAllSubscriptions(t, "example.com")

	// 3. Unsub
	resp, _ := http.PostForm(subURL+"/remove", values)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to api/subscribe failed with error %d", resp.StatusCode)
	}
	subs, _ := api.Database.GetSubscriptions()
	for _, sub := range subs {
		if sub.Domain == "example.com" && sub.Email == "me@example.com" {
			t.Fatalf("Remove subscription didn't work!")
		}
	}
	// 4. Resub
	testSubscribePost(t, "example.com", "me@example.com", http.StatusOK)
}
