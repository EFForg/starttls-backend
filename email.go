package main

import (
	"fmt"
	"github.com/EFForg/starttls-scanner/db"
	"net/smtp"
	"os"
	"strings"
	"time"
)

const validationEmailSubject = "Email validation for STARTTLS Policy List submission"
const validationEmailTemplate = `
Hey there!

It looks like you requested *%s* to be added to the STARTTLS Policy List, with hostnames %s. If this was you, visit

https://starttls-everywhere.eff.org/validate/%s

to confirm! If this wasn't you, please let us know at starttls-policy@eff.org.

Once you confirm your email, your domain will be queued for addition on *%s*. We will continue to run validation checks (https://starttls-everywhere.eff.org/policy-list#add) against your email server until then. On %s, *%s* will be added to the STARTTLS Policy List as long as it has continued to pass our tests!

Remember to read our guidelines (https://starttls-everywhere.eff.org/policy-list) about the requirements your mailserver must meet, and continue to meet, in order to stay on the list. If your mailserver ceases to meet these requirements at any point and is at risk of facing deliverability issues, we will notify you through this email address.

Thanks for helping us secure email for everyone :)
`

func validationEmailText(domain string, hostnames []string, token string, additionDate time.Time) string {
	dateString := additionDate.String()
	return fmt.Sprintf(validationEmailTemplate,
		domain,
		strings.Join(hostnames[:], ", "),
		token,
		dateString,
		dateString,
		domain)
}

func sendValidationEmail(domainInfo *db.DomainData, token string) error {
	emailContent := validationEmailText(domainInfo.Name, domainInfo.MXs, token,
		time.Now().Add(time.Hour*24*7))
	return sendEmail(validationEmailSubject, emailContent, domainInfo.Email)
}

func sendEmail(subject string, body string, address string) error {
	fromAddress := "no-reply@starttls-everywhere.org"
	message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s",
		fromAddress, address, subject, body)
	return smtp.SendMail("email-smtp.us-west-2.amazonaws.com:587",
		smtp.PlainAuth("", os.Getenv("SMTP_USERNAME"), os.Getenv("SMTP_PASSWORD"), "email-smtp.us-west-2.amazonaws.com"),
		fromAddress, []string{address}, []byte(message))
}
