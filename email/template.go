package email

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
