# STARTTLS Check
Evaluates an @mail domain on how secure its TLS settings are. First retrieves
all MX records for the domain, then performs a series of checks on each
discovered hostname's port 25.

## What does it check?
For each hostname found via a MX lookup, we check:
 - Can connect (over SMTP) on port 25
 - STARTTLS support
 - Presents valid certificate
 - TLS version up-to-date
 - Perfect forward secrecy

And we also check if your domain supports MTA-STS+TLSRPT by
 - Looking for and validating TXT records for `_mta-sts` and `_smtp-tlsrpt`
 - Looking for and validating a policy file hosted at
     `https://mta-sts.<domain>/.well-known/mta-sts.txt`

## Build

```
go get && go build
```

## Run

```
./starttls-check -domain <email domain> 
```

For instance, running `./starttls-check -domain gmail.com` will
check for MTA-STS support, and the TLS configurations (over SMTP) on
port 25 for all the MX domains for `gmail.com`.

NOTE: many ISPs block outbound port 25 to mitigate botnet e-mail spam. If you are on a residential IP, you might not be able to run this tool!

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

### Running sets of checks
```
./starttls-check -domain-file domains.txt
```
Will run the check across all of the e-mail domains in `domains.txt`,
and aggregate a report. The tool expects one domain on each line.

## Results
From a preliminary STARTTLS scan on the top 1000 alexa domains, performed 3/8/2018, we found:
 - 20.19% of 421 unique MX hostnames don't support STARTTLS.
 - 36.01% of the servers which support STARTTLS didn't present valid certificates.

Which seems like an improvement from results in [2014](https://research.google.com/pubs/pub43962.html), but we can do better!

## TODO
 - [X] Check MTA-STS support
 - [ ] Check DANE
 - [X] Policy generator
 - [X] Batch survey
 - [ ] Present recommendations for issues
 - [ ] Tests
