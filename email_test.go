package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestValidationEmailText(t *testing.T) {
	content := validationEmailText("example.com", "contact@example.com", []string{"mx.example.com, .mx.example.com"}, "abcd", "https://fake.starttls-everywhere.website")
	if !strings.Contains(content, "https://fake.starttls-everywhere.website/validate?abcd") {
		t.Errorf("E-mail formatted incorrectly.")
	}
}

func shouldPanic(t *testing.T, message string) {
	if r := recover(); r == nil {
		t.Errorf(message)
	}
}

func TestRequireMissingEnvPanics(t *testing.T) {
	varErrs := Errors{}
	requireEnv("FAKE_ENV_VAR", &varErrs)
	if len(varErrs) == 0 {
		t.Errorf("should have received an error")
	}
}

func TestRequireEnvConfig(t *testing.T) {
	requiredVars := map[string]string{
		"SMTP_USERNAME":         "",
		"SMTP_PASSWORD":         "",
		"SMTP_ENDPOINT":         "",
		"SMTP_PORT":             "",
		"SMTP_FROM_ADDRESS":     "",
		"FRONTEND_WEBSITE_LINK": ""}
	for varName := range requiredVars {
		requiredVars[varName] = os.Getenv(varName)
		os.Setenv(varName, "")
	}
	_, err := makeEmailConfigFromEnv(api.Database)
	if err == nil {
		t.Errorf("should have received multiple error from unset env vars")
	}
	for varName, varValue := range requiredVars {
		os.Setenv(varName, varValue)
	}
}

func TestParseSESNotification(t *testing.T) {
	inputs := [2]string{complaintJSON, bounceJSON}

	for _, input := range inputs {
		data := &blacklistRequest{}
		err := json.Unmarshal([]byte(input), data)
		if err != nil {
			t.Fatal(err)
		}
		if len(data.recipients) == 0 {
			t.Error("failed to parse recipients from notification")
		}
		for _, recipient := range data.recipients {
			if len(recipient.EmailAddress) == 0 {
				t.Error("failed to parse email address from recipient")
			}
		}
	}
}

func TestSendEmailToBlacklistedAddressFails(t *testing.T) {
	err := api.Database.PutBlacklistedEmail("fail@example.com", "bounce", "2017-07-21T18:47:13.498Z")
	if err != nil {
		t.Errorf("PutBlacklistedEmail failed: %v\n", err)
	}
	c := &emailConfig{database: api.Database}
	err = c.sendEmail("Subject", "Body", "fail@example.com")
	if !strings.Contains(err.Error(), "blacklisted") {
		t.Error("attempting to send mail to blacklisted address should fail")
	}
}

func TestHandleSESNotification(t *testing.T) {
	defer teardown()

	resp, err := http.Post(server.URL+"/sns?amazon_authorize_key="+os.Getenv("AMAZON_AUTHORIZE_KEY"),
		"application/json", strings.NewReader(complaintJSON))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("SES notification without key should return 200, got %d", resp.StatusCode)
	}

	blacklisted, err := api.Database.IsBlacklistedEmail("complaint@simulator.amazonses.com")
	if err != nil {
		t.Fatal(err)
	}
	if !blacklisted {
		t.Error("failed to blacklist email")
	}
}

func TestIgnoreNotificationWithoutKey(t *testing.T) {
	defer teardown()

	resp, err := http.Post(server.URL+"/sns?amazon_authorize_key=nope", "application/json",
		strings.NewReader(complaintJSON))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("SES notification without key should return 401, got %d", resp.StatusCode)
	}

	blacklisted, err := api.Database.IsBlacklistedEmail("complaint@simulator.amazonses.com")
	if err != nil {
		t.Fatal(err)
	}
	if blacklisted {
		t.Error("blacklisted notification with incorrect sns key")
	}
}

// Sample JSON cribbed from EFF Action Center tests - signatures may not verify.
// @todo update with more realistic examples once SNS is setup.

const complaintJSON = `{
"Type" : "Notification",
"MessageId" : "4cf6e02c-a704-5b80-81e7-b1c0e975734c",
"TopicArn" : "arn:aws:sns:us-west-2:486751131363:ses-complaint",
"Message" : "{\"notificationType\":\"Complaint\",\"complaint\":{\"complainedRecipients\":[{\"emailAddress\":\"complaint@simulator.amazonses.com\"}],\"timestamp\":\"2017-07-21T18:47:12.000Z\",\"feedbackId\":\"0101015d6679a0d7-02992932-6e45-11e7-8b8d-230f97f3b45c-000000\",\"userAgent\":\"Amazon SES Mailbox Simulator\",\"complaintFeedbackType\":\"abuse\"},\"mail\":{\"timestamp\":\"2017-07-21T18:47:10.000Z\",\"source\":\"actioncenter@eff.org\",\"sourceArn\":\"arn:aws:ses:us-west-2:486751131363:identity/eff.org\",\"sourceIp\":\"52.52.0.175\",\"sendingAccountId\":\"486751131363\",\"messageId\":\"0101015d66799783-25cb1bc6-44c7-408b-85b0-5303265489f6-000000\",\"destination\":[\"complaint@simulator.amazonses.com\"]}}",
"Timestamp" : "2017-07-21T18:47:13.498Z",
"SignatureVersion" : "1",
"Signature" : "L/DQz0vk1Lb95bGAhZJNRtMah4rholuL1NZvtRym/VA6ifWet/ZMn3NsJolHhbaQZIIlq+EV2gHRzDdtFB9eLm5Ia156VOxhv6dsbRMKlU5morLuF6GOSb1lRHTkJmv/vJJFoIuEKAVkhKhGofavbzCojBLhqubnJ8D4XGreM7jnprDbupRt+VsVokOa3zaWGsmqEkH9RnAejccexyZN7g3LEdq4vTz3qO8OCIXCDEe6B8/L1Y1DCZSbH/RD6AaDG6zyJt1EGZEApJODCZgazFlifWJWfeBb31UTfSQKZ+9b3FB8vJQ9FpaUs9m/XQxLn265+9ETLCzgs6TYq1k9Hg==",
"SigningCertURL" : "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-b95095beb82e8f6a046b3aafc7f4149a.pem",
"UnsubscribeURL" : "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:486751131363:ses-complaint:de9c5dc1-d0b7-411b-9410-bd3e4b760f1b"
}`

const bounceJSON = `{
"Type" : "Notification",
"MessageId" : "4cf6e02c-a704-5b80-81e7-b1c0e975734c",
"TopicArn" : "arn:aws:sns:us-west-2:486751131363:ses-bounce",
"Message" : "{\"notificationType\":\"Bounce\",\"bounce\":{\"bouncedRecipients\":[{\"emailAddress\":\"bounce@simulator.amazonses.com\"}],\"timestamp\":\"2017-07-21T18:47:12.000Z\",\"feedbackId\":\"0101015d6679a0d7-02992932-6e45-11e7-8b8d-230f97f3b45c-000000\",\"userAgent\":\"Amazon SES Mailbox Simulator\",\"bounceType\":\"permanent\"},\"mail\":{\"timestamp\":\"2017-07-21T18:47:10.000Z\",\"source\":\"actioncenter@eff.org\",\"sourceArn\":\"arn:aws:ses:us-west-2:486751131363:identity/eff.org\",\"sourceIp\":\"52.52.0.175\",\"sendingAccountId\":\"486751131363\",\"messageId\":\"0101015d66799783-25cb1bc6-44c7-408b-85b0-5303265489f6-000000\",\"destination\":[\"complaint@simulator.amazonses.com\"]}}",
"Timestamp" : "2017-07-21T18:47:13.498Z",
"SignatureVersion" : "1",
"Signature" : "L/DQz0vk1Lb95bGAhZJNRtMah4rholuL1NZvtRym/VA6ifWet/ZMn3NsJolHhbaQZIIlq+EV2gHRzDdtFB9eLm5Ia156VOxhv6dsbRMKlU5morLuF6GOSb1lRHTkJmv/vJJFoIuEKAVkhKhGofavbzCojBLhqubnJ8D4XGreM7jnprDbupRt+VsVokOa3zaWGsmqEkH9RnAejccexyZN7g3LEdq4vTz3qO8OCIXCDEe6B8/L1Y1DCZSbH/RD6AaDG6zyJt1EGZEApJODCZgazFlifWJWfeBb31UTfSQKZ+9b3FB8vJQ9FpaUs9m/XQxLn265+9ETLCzgs6TYq1k9Hg==",
"SigningCertURL" : "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-b95095beb82e8f6a046b3aafc7f4149a.pem",
"UnsubscribeURL" : "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:486751131363:ses-complaint:de9c5dc1-d0b7-411b-9410-bd3e4b760f1b"
}`
