# STARTTLS Check
Evaluates an @mail domain on how secure its TLS settings are. First retrieves all
MX records for the domain, then performs a series of checks on each discovered hostname's
port 25.

## What does it check?
For each hostname found via MX lookup, we check:
 - Can connect (over SMTP) on port 25
 - STARTTLS support
 - Presents valid certificate
 - TLS version up-to-date
 - Perfect forward secrecy

## Building and running

To build:
```
go get && go build
```

To run:
```
./starttls-check -domain <email domain>
```

For instance, running `./starttls-check -domain gmail.com` will check the TLS (over SMTP)
on port 25 for all the MX domains for `gmail.com`.


## TODO
 - [] Check MTA-STS support
 - [] Check DANE
 - [] Present recommendations for issues
 - [] Tests
