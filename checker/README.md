## Install

At the top of your Go file:
```
    import "github.com/sydneyli/starttls-check/checker"
```

## API

The most important API that we provide is
`checker.CheckDomain(domain string, mxHostnames []string) DomainResult;`
which performs all associated checks for a particular domain.

This first performs an MX lookup, then performs checks on each of the resulting hostnames.
The Status of DomainResult is inherited from the check status of the MX records with
the highest priority. So, the Status is set to Success only when all high priority hostnames
also have the Success status.

The reason we only require the highest-priority mailservers to pass is because many deploy dummy mailservers as a spam mitigation.

We do, however, provide the check information for the additional hostnames-- they just don't affect the status of the primary domain check.
