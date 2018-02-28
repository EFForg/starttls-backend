# STARTTLS Check
Evaluates an @mail domain on how secure its TLS settings are. First retrieves
all MX records for the domain, then performs a series of checks on each
discovered hostname's port 25.

## What does it check?
For each hostname found via MX lookup, we check:
 - Can connect (over SMTP) on port 25
 - STARTTLS support
 - Presents valid certificate
 - TLS version up-to-date
 - Perfect forward secrecy
And we also check if your domain supports MTA-STS+TLSRPT by
 - Looking for and validating TXT records for `_mta-sts` and `_smtp-tlsrpt`
 - Looking for and validating a policy file hosted at
     `https://mta-sts.<domain>/.well-known/mta-sts.txt`

## Building and running

To build:
```
go get && go build
```

To run:
```
./starttls-check -domain <email domain> 
```

For instance, running `./starttls-check -domain gmail.com -starttls` will
check for MTA-STS support, and the TLS configurations (over SMTP) on
port 25 for all the MX domains for `gmail.com`.

### Running individual checks

You can add the flags `-mtasts` or `-starttls` in order to run an individual
suite of checks. Run with the flag `-help` set for more info!

All checks are enabled by default. If you wish to only run a single suite of
checks, specifying any check via a flag will disable all checks other than
the ones explicitly specified. For instance, these two commands are
functionally equivalent:
```
./starttls-check -domain example.com
./starttls-check -domain example.com -mtasts -starttls
```
However, running:
```
./starttls-check -domain example.com -starttls
```
will only perform the TLS checks.


## TODO
 - [X] Check MTA-STS support
 - [ ] Check DANE
 - [ ] Policy generator
 - [ ] Present recommendations for issues
 - [ ] Tests
