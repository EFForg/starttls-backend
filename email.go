package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"

	"github.com/EFForg/starttls-scanner/db"
)

// Configuration variables needed to submit emails for sending, as well as
// to generate the templates.
type emailConfig struct {
	auth               smtp.Auth
	username           string
	password           string
	submissionHostname string
	port               string
	sender             string
	website            string // Needed to generate email template text.
}

const validationEmailSubject = "Email validation for STARTTLS Policy List submission"
const validationEmailTemplate = `
Hey there!

It looks like you requested *%[1]s* to be added to the STARTTLS Policy List, with hostnames %[2]s and contact email %[5]s. If this was you, visit

 %[3]s/validate?%[4]s

to confirm! If this wasn't you, please let us know at starttls-policy@eff.org.

Once you confirm your email address, your domain will be queued for addition some time in the next couple of weeks. We will continue to run validation checks (%[3]s/policy-list#add) against your email server until then. *%[1]s* will be added to the STARTTLS Policy List as long as it has continued to pass our tests!

Remember to read our guidelines (%[3]s/policy-list) about the requirements your mailserver must meet, and continue to meet, in order to stay on the list. If your mailserver ceases to meet these requirements at any point and is at risk of facing deliverability issues, we will notify you through this email address.

We also recommend signing up for the STARTTLS Everywhere mailing list at https://lists.eff.org/mailman/listinfo/starttls-everywhere in order to stay up to date on new features, changes to policies, and updates to the project. (This is a low-volume mailing list.)

Thanks for helping us secure email for everyone :)
`

func makeEmailConfigFromEnv() (emailConfig, error) {
	// create config
	varErrs := Errors{}
	c := emailConfig{
		username:           requireEnv("SMTP_USERNAME", &varErrs),
		password:           requireEnv("SMTP_PASSWORD", &varErrs),
		submissionHostname: requireEnv("SMTP_ENDPOINT", &varErrs),
		port:               requireEnv("SMTP_PORT", &varErrs),
		sender:             requireEnv("SMTP_FROM_ADDRESS", &varErrs),
		website:            requireEnv("FRONTEND_WEBSITE_LINK", &varErrs),
	}
	if len(varErrs) > 0 {
		return c, varErrs
	}
	log.Printf("Establishing auth connection with SMTP server %s", c.submissionHostname)
	// create auth
	client, err := smtp.Dial(fmt.Sprintf("%s:%s", c.submissionHostname, c.port))
	if err != nil {
		return c, err
	}
	defer client.Close()
	err = client.StartTLS(&tls.Config{ServerName: c.submissionHostname})
	if err != nil {
		return c, fmt.Errorf("SMTP server doesn't support STARTTLS")
	}
	ok, auths := client.Extension("AUTH")
	if !ok {
		return c, fmt.Errorf("remote SMTP server doesn't support any authentication mechanisms")
	}
	if strings.Contains(auths, "PLAIN") {
		c.auth = smtp.PlainAuth("", c.username, c.password, c.submissionHostname)
	} else if strings.Contains(auths, "CRAM-MD5") {
		c.auth = smtp.CRAMMD5Auth(c.username, c.password)
	} else {
		return c, fmt.Errorf("SMTP server doesn't support PLAIN or CRAM-MD5 authentication")
	}
	return c, nil
}

func validationAddress(domainInfo *db.DomainData) string {
	return fmt.Sprintf("postmaster@%s", domainInfo.Name)
}

func validationEmailText(domain string, contactEmail string, hostnames []string, token string, website string) string {
	return fmt.Sprintf(validationEmailTemplate,
		domain, strings.Join(hostnames[:], ", "), website, token, contactEmail)
}

// SendValidation sends a validation e-mail for the domain outlined by domainInfo.
// The validation link is generated using a token.
func (c emailConfig) SendValidation(domainInfo *db.DomainData, token string) error {
	emailContent := validationEmailText(domainInfo.Name, domainInfo.Email, domainInfo.MXs, token,
		c.website)
	return c.sendEmail(validationEmailSubject, emailContent, validationAddress(domainInfo))
}

func (c emailConfig) sendEmail(subject string, body string, address string) error {
	blacklisted, err := api.Database.IsBlacklistedEmail(address)
	if err != nil {
		return err
	}
	if blacklisted {
		return fmt.Errorf("address %s is blacklisted", address)
	}
	message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s",
		c.sender, address, subject, body)
	return smtp.SendMail(fmt.Sprintf("%s:%s", c.submissionHostname, c.port),
		c.auth,
		c.sender, []string{address}, []byte(message))
}

type snsWrapper struct {
	Type      string
	MessageID string
	Message   string
	Timestamp string
}

type snsMessage struct {
	NotificationType string `json:"notificationType"`
	Complaint        struct {
		ComplainedRecipients []struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"complainedRecipients"`
		ComplaintFeedbackType string `json:"complaintFeedbackType"`
		Timestamp             string `json:"timestamp"`
	} `json:"complaint"`
}

func parseComplaintJSON(messageJSON []byte) (snsMessage, error) {
	var wrapper snsWrapper
	if err := json.Unmarshal(messageJSON, &wrapper); err != nil {
		return snsMessage{}, fmt.Errorf("failed to load complaint wrapper: %v", err)
	}

	// Notification body is string encoded, so we have to unmarshall twice.
	var complaint snsMessage
	if err := json.Unmarshal([]byte(wrapper.Message), &complaint); err != nil {
		return snsMessage{}, fmt.Errorf("failed to load complaint: %v", err)
	}
	return complaint, nil
}

func handleSESNotification(w http.ResponseWriter, r *http.Request) {
	keyParam := r.URL.Query()["amazon_authorize_key"]
	if len(keyParam) == 0 || keyParam[0] != os.Getenv("AMAZON_AUTHORIZE_KEY") {
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// Log to sentry and return
	}
	complaint, err := parseComplaintJSON(body)
	if err != nil {
		// Log to sentry and return
	}

	for _, recipient := range complaint.Complaint.ComplainedRecipients {
		err = api.Database.PutBlacklistedEmail(recipient.EmailAddress, complaint.NotificationType, complaint.Complaint.Timestamp)
		if err != nil {
			// Log to sentry
		}
	}
}
