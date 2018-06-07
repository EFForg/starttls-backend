package main

import (
	"fmt"
	"github.com/EFForg/starttls-scanner/db"
	"net/smtp"
	"strings"
	"time"
)

// Configuration variables needed to submit emails for sending, as well as
// to generate the templates.
type emailConfig struct {
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

 %s/validate/%s

to confirm! If this wasn't you, please let us know at starttls-policy@eff.org or by replying to this e-mail.

Once you confirm your email address, your domain will be queued for addition on *%s*. We will continue to run validation checks (%s/policy-list#add) against your email server until then. On %s, *%s* will be added to the STARTTLS Policy List as long as it has continued to pass our tests!

Remember to read our guidelines (%s/policy-list) about the requirements your mailserver must meet, and continue to meet, in order to stay on the list. If your mailserver ceases to meet these requirements at any point and is at risk of facing deliverability issues, we will notify you through this email address.

Thanks for helping us secure email for everyone :)
`

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
		smtp.PlainAuth("", c.username, c.password, c.submissionHostname),
		c.sender, []string{address}, []byte(message))
}
