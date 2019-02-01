package main

import (
	"fmt"
	"log"
	"net/http"
)

// SubscribeConfirm is the handler for /api/subscribe/confirm
//   POST /api/subscribe/confirm?token=<token>
//        token: Token nonce to redeem
func (api API) SubscribeConfirm(r *http.Request) APIResponse {
	token, err := getParam("token", r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	if r.Method != http.MethodPost {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/subscribe/confirm only accepts POST requests"}
	}
	_, err = api.Database.ConfirmSubscription(token)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest,
			Message: "Token already expired! Re-submit the subscription form to generate a new one."}
	}
	return APIResponse{
		StatusCode: http.StatusOK,
		Message:    "confirmed yay"}
}

// SubscribeRemove is the handler for /api/subscribe/remove
//   POST /api/subscribe/remove?domain=<domain>,email=<email>
func (api API) SubscribeRemove(r *http.Request) APIResponse {
	// Retrieve domain param
	domain, err := getASCIIDomain(r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	email, err := getParam("email", r)
	if err != nil {
		email = validationAddress(domain)
	}
	err = api.Database.RemoveSubscription(domain, email)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest,
			Message: "You're not yet subscribed!"}
	}
	return APIResponse{
		StatusCode: http.StatusOK,
		Message:    "confirmed yay"}
}

// Subscribe is the handler for /api/subscribe
//   POST /api/subscribe?domain=<domain>&email=<email>
//        domain: Mail domain to occasionally check.
//        email (optional): Contact email to send updates to.
func (api API) Subscribe(r *http.Request) APIResponse {
	// Retrieve domain param
	domain, err := getASCIIDomain(r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	email, err := getParam("email", r)
	if err != nil {
		email = validationAddress(domain)
	}
	if r.Method != http.MethodPost {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/subscribe only accepts POST requests"}
	}
	// POST: Insert this domain into the subs DB
	// 1. Add subscrpition
	token, err := api.Database.PutSubscription(domain, email)
	if err != nil {
		return APIResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "You're already subscribed!",
		}
	}
	// 2. Send validation email
	err = api.Emailer.SendSubscriptionValidation(domain, email, token)
	if err != nil {
		log.Print(err)
		return APIResponse{StatusCode: http.StatusInternalServerError,
			Message: "Unable to send subscription validation e-mail"}
	}
	// domainData.State = Unvalidated
	// or queued?
	return APIResponse{
		StatusCode: http.StatusOK,
		Response:   fmt.Sprintf("Thank you for submitting your domain. Please check postmaster@%s to validate that you control the domain.", domain),
	}
}
