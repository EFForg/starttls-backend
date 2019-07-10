# STARTTLS Everywhere Backend API

[![Build Status](https://travis-ci.com/EFForg/starttls-backend.svg?branch=master)](https://travis-ci.org/EFForg/starttls-backend)
[![Coverage Status](https://coveralls.io/repos/github/EFForg/starttls-backend/badge.svg?branch=master)](https://coveralls.io/github/EFForg/starttls-backend?branch=master)

starttls-backend is the JSON backend for starttls-everywhere.org. It provides endpoints to run security checks against email domains and manage the status of those domain's on EFF's [STARTTLS Everywhere policy list](https://github.com/EFForg/starttls-everywhere).

## Setup
1. Install `go` and `postgres`.
2. Download the project and copy the configuration file:
```
go get github.com/EFForg/starttls-backend
cd $GOPATH/github.com/EFForg/starttls-backend
cp .env.example .env
cp .env.test.example .env.test
```
3. Edit `.env` and `.env.test` with your postgres credentials and any other changes.
4. Ensure `postgres` is running, then run `db/scripts/init_tables.sql` in the appropriate postgres DBs in order to initialize your development and test databases.
5. Build the scanner and start serving requests:
```
go build
./starttls-backend
```

### Via Docker
```
cp .env.example .env
cp .env.test.example .env.test
docker-compose build
docker-compose up
```

To automatically on container start, set `DB_MIGRATE=true` in the `.env` file.

## Testing

Test all packages in this repo with
```
go test -v ./...
```

The `main` and `db` packages contain integration tests that require a successful connection to the Postgres database. The remaining packages do not require the database to pass tests.

## Configuration

### No-scan domains
In case of complaints or abuse, we may not want to continually scan some domains. You can set the environment variable `DOMAIN_BLACKLIST` to point to a file with a list of newline-separated domains. Attempting to scan those domains from the public-facing website will result in error codes.

## Scan API

Our API objects can look a bit complicated! There's lots of information contained in a TLS scan.
To request a scan:
```
POST /api/scan
  { "domain": "example.com" }
```

Let's break down exactly what each part of this giant nested response means. All API responses, not just scans, are wrapped in a JSON object, like:
```
{
    status_code: 200,
    message: "",
    response: <response data>
}
```
Or even:
```
{
    status_code: 400,
    message: "query parameter domain not specified",
    response: {}
}
```
The status codes always correspond with the HTTP status that is given for the response. `message` provides more context into why your request failed.

### Scan responses

Here's an abbreviated scan response. There's extra information on these objects that help
describe the errors we encountered.
```
{
    domain: "example.com",
    scandata: {
        status: 0,
        results: {  // Individual hostname check results
            "mx.example.com": {
                "status": 0,
                "checks": {
                    "connectivity": { "status": 0 },
                    "certificate": { "status": 0 },
                    "starttls": { "status": 0 },
                    "version": { "status": 0 },
                }
            }
            "dummy.example.com": {
                "status": 3,
                "checks": {
                    "connectivity": {
                        "status": 3,
                        "messages": [ "Error: Could not establish connection" ]
                    },
                }
            },
        },
        preferred_hostnames: ["mx.example.com"], // Hostnames we were able to connect to
        extra_results: {"policylist": { "status": 0 }},
    },
    timestamp: 0,
    version: 1,
}
```

The meat of the response is in `scandata`, which is a JSON-ification of the `DomainResult` structure returned from the `checker` package.

### Domain results

Here's a quick synopsis of the fields you see in a domain response:

 - `domain`: the domain name that the scan was performed on.
 - `status`: Whether the check succeeded overall, and some more specific common failure types. Types 4-6 are types of test failures that are particularly common.
    - 0: Success, all TLS tests passed.
    - 1: Warning, at least one TLS test produced a warning.
    - 2: Failure, at least one TLS test failed.
    - 3: Error, something went wrong during the test.
    - 4: NoSTARTTLS, at least one of your mailboxes did not advertise STARTTLS.
    - 5: CouldNotConnect, could not connect to any mailbox.
    - 6: BadHostnameFailure, one of your mailbox's provided certificates didn't match its hostname.
 - `message`: A more detailed description of the failure type.
 - `preferred_hostnames`: A misnomer, but refers to mailboxes that passed the connectivity test.
 - `mta_sts`: result for MTA STS check.
 - `extra_results`: A map of other security checks for this domain.
 - `results`: A map of mailbox hostnames to their individual results.
 - `timestamp`: Timestamp of when the scan was performed.
 - `version`: The scan API's version when it was performed.

### Hostname results

Here's a sample, 
```
{
    "status": 0,
    "checks": {
        "connectivity": { "status": 0 },
        "certificate": {
            "status": 2,
            "messages": ["Hostname doesn't match any name in certificate",
                         "Certificate root is not trusted"]
        },
        "starttls": { "status": 0 },
        "version": { "status": 0 },
    }
}
```

 - `checks`: A result can have a suite of checks. `checks` is a map from a particular check name to its result.
 - `status`: The status of a particular check, or the overall suite. Can be 0 through 3, which are `Success`, `Warning`, `Failure`, `Error`. The overall suite status takes the max status of all the sub-checks.
 - `messages`: If status of a check isn't success, messages is where all warnings and failure messages go.

### What do we scan for?

Right now, these are the checks we perform.

##### Hostname-level scans
These scans are performed for every hostname-- that is, we try these things for every MX we find for the given domain.

 * *Connectivity*: This one is performed first. It's common for mailservers to use dummy MX records as a spam-prevention tactic, so a hostname that fails to connect doesn't automatically fail the entire TLS scan, unless *no* hostnames succeed in connectivity.
 * *STARTTLS*: The checker first connects to the mailbox and looks for a STARTTLS support banner. Then, we actively try to initiate a STARTTLS session.
 * *Certificate*: The checker checks for certificate validity, which includes (1) chaining to a valid root in Mozilla's CA store, (2) the hostname matching the certificate, and (3) the certificate being not expired.
 * *Version*: The checker checks your mailserver doesn't support obsolete and insecure protocols prior to TLS 1.0.

##### Domain-level scans
These scans are performed for the domain itself.

 * *MTA-STS* We check to see whether your email domain follows the MTA-STS specification, and that the MTA-STS policy we find is valid.
 * *Policy List* We check to see whether your email domain is on our policy list, or queued to be added.

### Rate-limiting, caching, and no-scan lists

We rate-limit several endpoints to prevent abuse and reduce load on our servers. By default, scan requests are cached-- if you're consistently updating your servers and want to check to see if it's passing, we recommend waiting a few minutes and re-scanning.

In case of complaints of abuse, we may not want to continually scan some domains, who can elect to prevent automated scans from this service.
