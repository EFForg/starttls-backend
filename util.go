package main

import (
	"log"
	"regexp"
	"strings"
)

// Match domain names according to RFC 1035
// * Neither suffix nor prefix; should not end or start with `.`
const matchDNS = `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*$`

func validDomainName(s string) bool {
	if len(s) < 1 || !strings.Contains(s, ".") {
		return false
	}
	ok, err := regexp.MatchString(matchDNS, s)
	if err != nil {
		log.Printf("Regex for DNS matching failed with error %v", err)
		return false
	}
	return ok
}
