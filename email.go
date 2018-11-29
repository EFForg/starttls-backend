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

	"github.com/EFForg/starttls-backend/db"
	raven "github.com/getsentry/raven-go"
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
	database           db.Database
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

func makeEmailConfigFromEnv(database db.Database) (emailConfig, error) {
	// create config
	varErrs := Errors{}
	c := emailConfig{
		username:           requireEnv("SMTP_USERNAME", &varErrs),
		password:           requireEnv("SMTP_PASSWORD", &varErrs),
		submissionHostname: requireEnv("SMTP_ENDPOINT", &varErrs),
		port:               requireEnv("SMTP_PORT", &varErrs),
		sender:             requireEnv("SMTP_FROM_ADDRESS", &varErrs),
		website:            requireEnv("FRONTEND_WEBSITE_LINK", &varErrs),
		database:           database,
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
	blacklisted, err := c.database.IsBlacklistedEmail(address)
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

// Recipients lists the email addresses that have triggered a bounce or complaint.
type Recipients []struct {
	EmailAddress string `json:"emailAddress"`
}

type blacklistRequest struct {
	reason     string
	timestamp  string
	recipients Recipients
	raw        string
}

type ravenExtraContent string

// Class satisfies raven's Interface interface so we can send this as extra context.
// https://github.com/getsentry/raven-go/issues/125
func (r ravenExtraContent) Class() string {
	return "extra"
}

func (r ravenExtraContent) MarshalJSON() ([]byte, error) {
	return []byte(r), nil
}

// UnmarshallJSON wrangles the JSON posted by AWS SNS into something easier to access
// and generalized across notification types.
func (r *blacklistRequest) UnmarshalJSON(b []byte) error {
	// We need to start by unmarshalling Message into a string because the field contains stringified JSON.
	// See email_test.go for examples.
	var wrapper struct {
		Message   string
		Timestamp string
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return fmt.Errorf("failed to load notification wrapper: %v", err)
	}

	type Complaint struct {
		*Recipients `json:"complainedRecipients"`
	}

	type Bounce struct {
		*Recipients `json:"bouncedRecipients"`
	}

	// We'll unmarshall the list of bounced or complained emails into
	// &recipients.  Only one of Complaint or Bounce will contain data, so we can
	// reuse &recipients to capture whichever field holds the list.
	var recipients Recipients
	msg := struct {
		NotificationType string `json:"notificationType"`
		Complaint        `json:"complaint"`
		Bounce           `json:"bounce"`
	}{
		Complaint: Complaint{Recipients: &recipients},
		Bounce:    Bounce{Recipients: &recipients},
	}

	if err := json.Unmarshal([]byte(wrapper.Message), &msg); err != nil {
		return fmt.Errorf("failed to load notification message: %v", err)
	}

	*r = blacklistRequest{
		raw:        wrapper.Message,
		timestamp:  wrapper.Timestamp,
		reason:     msg.NotificationType,
		recipients: recipients,
	}
	return nil
}

// handleSESNotification handles AWS SES bounces and complaints submitted to a webhook
// via AWS SNS (Simple Notification Service).
// The SNS webhook is configured to include a secret API key stored in the environment.
func handleSESNotification(database db.Database) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		keyParam := r.URL.Query()["amazon_authorize_key"]
		if len(keyParam) == 0 || keyParam[0] != os.Getenv("AMAZON_AUTHORIZE_KEY") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			raven.CaptureError(err, nil)
			return
		}

		data := &blacklistRequest{}
		err = json.Unmarshal(body, data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			raven.CaptureError(err, nil, ravenExtraContent(body))
			return
		}

		tags := map[string]string{"notification_type": data.reason}
		raven.CaptureMessage("Received SES notification", tags, ravenExtraContent(data.raw))

		for _, recipient := range data.recipients {
			err = database.PutBlacklistedEmail(recipient.EmailAddress, data.reason, data.timestamp)
			if err != nil {
				raven.CaptureError(err, nil)
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}
