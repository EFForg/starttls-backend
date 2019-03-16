package main

import (
	"fmt"
	"strings"
	"time"
)

// File containing email templates.

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

const successEmailSubject = "Success! The testing period for %s has passed."
const successEmailTemplate = `
Hey there!
 
Congratulations! Your domain's TLS policy *%[1]s* with hostnames %[2]s has been on the list successfully for the past %[3]d weeks.

We'll be upgrading your domain's policy from *testing* to *enforce* in the next week. Thanks for helping us secure email for everyone :)
`

const failureEmailSubject = "We found an issue with *%[1]s*'s TLS policy!"
const failureEmailTemplate = `
Hey there!
 
We started testing *%[1]s*'s TLS policy starting on %[2]s. Just now, we found an issue with your policy:

 %[3]s

Since your domain was still in *testing* mode, for now we'll be taking it off the STARTTLS policy list. Once you've resolved the issue, try adding your domain again at %[4]s/add-domain .

If you have any questions about the above or think that this report was in error, please let us know at starttls-policy@eff.org.

Thanks for helping us secure email for everyone :)
`

func validationEmail(domain string, contactEmail string, hostnames []string, token string, website string) (string, string) {
	return validationEmailSubject, fmt.Sprintf(validationEmailTemplate,
		domain, strings.Join(hostnames[:], ", "), website, token, contactEmail)
}

func successEmail(domain string, hostnames []string, weeks int) (string, string) {
	return fmt.Sprintf(successEmailSubject, domain), fmt.Sprintf(successEmailTemplate,
		domain, strings.Join(hostnames[:], ", "), weeks)
}

func failureEmail(domain string, queueStart time.Time, errorMessage string, website string) (string, string) {
	return fmt.Sprintf(failureEmailSubject, domain), fmt.Sprintf(failureEmailTemplate, domain, queueStart.Format("Jan 2, 2006"), errorMessage, website)
}
