package util

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Match domain names according to RFC 1035
// * Neither suffix nor prefix; should not end or start with `.`
const matchDNS = `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*$`

// ValidDomainName returns true if given name is a valid FQDN.
func ValidDomainName(s string) bool {
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

// ValidPort normalizes a portstring like "80" to ":80".
func ValidPort(port string) (string, error) {
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("Given portstring %s is invalid", port)
	}
	return fmt.Sprintf(":%s", port), nil
}

// Errors composites multiple errors.
type Errors []error

// Error composites the messages from all contained errors.
func (e Errors) Error() string {
	if len(e) == 1 {
		return e[0].Error()
	}
	msg := "multiple errors:"
	for _, err := range e {
		msg += "\n" + err.Error()
	}
	return msg
}

// Add adds another error to this composite.
func (e Errors) Add(err error) Errors {
	if err != nil {
		return append(e, err)
	}
	return e
}

// RequireEnv retrieves environment variable varName. If not set as env
// variable, panic and exit.
//   varName is the OS environment variable name.
//   errors is a composite errors object to add to if a variable is not set.
func RequireEnv(varName string, errors *Errors) string {
	envVar := os.Getenv(varName)
	if len(envVar) == 0 {
		*errors = errors.Add(fmt.Errorf("expected environment variable %s to be set", varName))
	}
	return envVar
}
