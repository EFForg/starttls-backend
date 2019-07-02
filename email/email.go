package email

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"strings"

	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/util"
)

type blacklistStore interface {
	PutBlacklistedEmail(email string, reason string, timestamp string) error
	IsBlacklistedEmail(string) (bool, error)
}

// Config stores variables needed to submit emails for sending, as well as
// to generate the templates.
type Config struct {
	auth               smtp.Auth
	username           string
	password           string
	submissionHostname string
	port               string
	sender             string
	website            string // Needed to generate email template text.
	database           blacklistStore
}

// MakeConfigFromEnv initializes our email config object with
// environment variables.
func MakeConfigFromEnv(database db.Database) (Config, error) {
	// create config
	varErrs := util.Errors{}
	c := Config{
		username:           util.RequireEnv("SMTP_USERNAME", &varErrs),
		password:           util.RequireEnv("SMTP_PASSWORD", &varErrs),
		submissionHostname: util.RequireEnv("SMTP_ENDPOINT", &varErrs),
		port:               util.RequireEnv("SMTP_PORT", &varErrs),
		sender:             util.RequireEnv("SMTP_FROM_ADDRESS", &varErrs),
		website:            util.RequireEnv("FRONTEND_WEBSITE_LINK", &varErrs),
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

// ValidationAddress Returns default validation address for this domain.
func ValidationAddress(domain string) string {
	return fmt.Sprintf("postmaster@%s", domain)
}

func validationEmailText(domain string, contactEmail string, hostnames []string, token string, website string) string {
	return fmt.Sprintf(validationEmailTemplate,
		domain, strings.Join(hostnames[:], ", "), website, token, contactEmail)
}

// SendValidation sends a validation e-mail for the domain outlined by domainInfo.
// The validation link is generated using a token.
func (c Config) SendValidation(domain *models.PolicySubmission, token string) error {
	emailContent := validationEmailText(domain.Name, domain.Email, domain.Policy.MXs, token,
		c.website)
	return c.sendEmail(validationEmailSubject, emailContent, ValidationAddress(domain.Name))
}

func (c Config) sendEmail(subject string, body string, address string) error {
	blacklisted, err := c.database.IsBlacklistedEmail(address)
	if err != nil {
		return err
	}
	if blacklisted {
		return fmt.Errorf("address %s is blacklisted", address)
	}
	message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s",
		c.sender, address, subject, body)
	if c.submissionHostname == "" {
		log.Println("Warning: email host not configured, not sending email")
		log.Println(message)
		return nil
	}
	return smtp.SendMail(fmt.Sprintf("%s:%s", c.submissionHostname, c.port),
		c.auth,
		c.sender, []string{address}, []byte(message))
}

// Recipients lists the email addresses that have triggered a bounce or complaint.
type Recipients []struct {
	EmailAddress string `json:"emailAddress"`
}

// BlacklistRequest represents a submission for a particular email address to be blacklisted.
type BlacklistRequest struct {
	Reason     string
	Timestamp  string
	Recipients Recipients
	Raw        string
}

// UnmarshalJSON wrangles the JSON posted by AWS SNS into something easier to access
// and generalized across notification types.
func (r *BlacklistRequest) UnmarshalJSON(b []byte) error {
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

	*r = BlacklistRequest{
		Raw:        wrapper.Message,
		Timestamp:  wrapper.Timestamp,
		Reason:     msg.NotificationType,
		Recipients: recipients,
	}
	return nil
}
