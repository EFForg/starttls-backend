package main

import (
	"crypto/tls"
	"fmt"
	"github.com/EFForg/starttls-scanner/db"
	"log"
	"net/smtp"
	"strings"
	"time"
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

It looks like you requested *%s* to be added to the STARTTLS Policy List, with hostnames %s. If this was you, visit

 %s/validate?%s

to confirm! If this wasn't you, please let us know at starttls-policy@eff.org or by replying to this e-mail.

Once you confirm your email address, your domain will be queued for addition on *%s*. We will continue to run validation checks (%s/policy-list#add) against your email server until then. On %s, *%s* will be added to the STARTTLS Policy List as long as it has continued to pass our tests!

Remember to read our guidelines (%s/policy-list) about the requirements your mailserver must meet, and continue to meet, in order to stay on the list. If your mailserver ceases to meet these requirements at any point and is at risk of facing deliverability issues, we will notify you through this email address.

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
		return c, fmt.Errorf("%s SMTP server doesn't support PLAIN or CRAM-MD5 authentication")
	}
	return c, nil
}

func validationEmailText(domain string, hostnames []string, token string, additionDate time.Time, website string) string {
	dateString := additionDate.String()
	return fmt.Sprintf(validationEmailTemplate,
		domain, strings.Join(hostnames[:], ", "),
		website, token,
		dateString, website, dateString, domain,
		website)
}

// SendValidation sends a validation e-mail for the domain outlined by domainInfo.
// The validation link is generated using a token.
func (c emailConfig) SendValidation(domainInfo *db.DomainData, token string) error {
	emailContent := validationEmailText(domainInfo.Name, domainInfo.MXs, token,
		time.Now().Add(time.Hour*24*7), c.website)
	return c.sendEmail(validationEmailSubject, emailContent, domainInfo.Email)
}

func (c emailConfig) sendEmail(subject string, body string, address string) error {
	message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s",
		c.sender, address, subject, body)
	return smtp.SendMail(fmt.Sprintf("%s:%s", c.submissionHostname, c.port),
		c.auth,
		c.sender, []string{address}, []byte(message))
}
