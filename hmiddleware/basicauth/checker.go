package basicauth

import (
	"crypto/subtle"
	"strings"

	"github.com/pkg/errors"
)

// Credentials is a set of credentials with the added functionality of
// decoding.
type Credentials []Credential

// Decode implements the envdecode contract, allowing Credentials to be used in
// config structs.
func (c *Credentials) Decode(repl string) error {
	s := strings.Split(repl, ";")
	result := make([]Credential, 0, len(s))
	for _, part := range s {
		cred, err := parseCredential(part)
		if err != nil {
			return err
		}
		result = append(result, cred)
	}

	*c = result
	return nil
}

// Credential is a valid username/password pair used to authenticate HTTP
// requests using basic auth.
type Credential struct {
	Username string
	Password string
}

var errMalformedCredentials = errors.New("malformed credentials")

func parseCredential(credential string) (Credential, error) {
	parts := strings.SplitN(credential, ":", 2)
	if len(parts) != 2 {
		return Credential{}, errMalformedCredentials
	} else if parts[0] == "" && parts[1] == "" {
		return Credential{}, errMalformedCredentials
	}
	return Credential{Username: parts[0], Password: parts[1]}, nil
}

// Checker stores a set of valid credentials to be used when authenticating
// HTTP requests using basic auth.
type Checker struct {
	credentials   []Credential
	roleValidator RoleValidator
}

// RoleValidator providers Validate() which returns true
// if a role has access to a particular request method.
type RoleValidator interface {
	Validate(role, method string) bool
}

// NewChecker returns a basic auth checker configured to use credentials
// when checking for valid authentication.
func NewChecker(credentials []Credential) *Checker {
	return &Checker{
		credentials: credentials,
	}
}

// WithRoleValidator sets the roleValidator on a Checker.
func (c *Checker) WithRoleValidator(rv RoleValidator) {
	c.roleValidator = rv
}

// Valid is true if username and password represent acceptable credentials.
func (c *Checker) Valid(username, password string) bool {
	for _, cred := range c.credentials {
		userValid := subtle.ConstantTimeCompare([]byte(cred.Username), []byte(username)) == 1
		passwordValid := subtle.ConstantTimeCompare([]byte(cred.Password), []byte(password)) == 1
		if userValid && passwordValid {
			return true
		}
	}
	return false
}
