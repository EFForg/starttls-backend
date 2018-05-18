# STARTTLS Check
Evaluates an @mail domain on how secure its TLS settings are. First retrieves
all MX records for the domain, then performs a series of checks on each
discovered hostname's port 25.

## What does it check?
For each hostname found via a MX lookup, we check:
 - Can connect (over SMTP) on port 25
 - STARTTLS support
 - Presents a valid certificate
 - TLS version up-to-date
 - Secure TLS ciphers

## Build

```
go get && go build
```

## Run

```
./starttls-check -domain <email domain> 
```

For instance, running `./starttls-check -domain gmail.com` will
check for the TLS configurations (over SMTP) on port 25 for all the MX domains for `gmail.com`.

NOTE: many ISPs block outbound port 25 to mitigate botnet e-mail spam. If you are on a residential IP, you might not be able to run this tool!

## Results
From a preliminary STARTTLS scan on the top 1000 alexa domains, performed 3/8/2018, we found:
 - 20.19% of 421 unique MX hostnames don't support STARTTLS.
 - 36.01% of the servers which support STARTTLS didn't present valid certificates.
    - We're not sure how to define valid certificates. On manual inspection, although many certificates are self-signed, it seems that many of these certs are issued for other subdomains owned by the same entity.

Seems like an improvement from results in [2014](https://research.google.com/pubs/pub43962.html), but we can do better!


## TODO
 - [ ] Check DANE
 - [ ] Present recommendations for issues
 - [ ] Tests
