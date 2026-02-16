package plugin

import (
	"context"
	"errors"
)

var (
	// ErrUserNotFound is returned when a user is not found in the credential store.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserDisabled is returned when a user exists but is disabled.
	ErrUserDisabled = errors.New("user is disabled")
	// ErrDatabaseNotAllowed is returned when a user is not allowed to connect to the requested database.
	ErrDatabaseNotAllowed = errors.New("database not allowed for user")
)

// UserCredential represents a user's stored credentials and access configuration.
type UserCredential struct {
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`               // Plaintext password (used to derive hashes at runtime)
	AuthMethods []string `yaml:"auth_methods,omitempty"` // Allowed auth methods: ["md5", "scram-sha-256", "cleartext"]
	Roles       []string `yaml:"roles,omitempty"`        // Roles for authorization
	Databases   []string `yaml:"databases,omitempty"`    // Allowed databases (empty = all)
	Enabled     *bool    `yaml:"enabled,omitempty"`      // Whether the user is enabled (default: true)
}

// IsEnabled returns true if the user is enabled (defaults to true if not set).
func (u *UserCredential) IsEnabled() bool {
	if u.Enabled == nil {
		return true
	}
	return *u.Enabled
}

// IsDatabaseAllowed checks if the user can connect to the given database.
// An empty Databases list means all databases are allowed.
func (u *UserCredential) IsDatabaseAllowed(database string) bool {
	if len(u.Databases) == 0 {
		return true
	}
	for _, db := range u.Databases {
		if db == database || db == "*" {
			return true
		}
	}
	return false
}

// SupportsAuthMethod checks if the user supports the given auth method.
// An empty AuthMethods list means all methods are supported.
func (u *UserCredential) SupportsAuthMethod(method AuthType) bool {
	if len(u.AuthMethods) == 0 {
		return true
	}
	for _, m := range u.AuthMethods {
		if AuthType(m) == method {
			return true
		}
	}
	return false
}

// CredentialStore is the interface for looking up user credentials.
type CredentialStore interface {
	// LookupUser returns the user's credentials or ErrUserNotFound.
	LookupUser(ctx context.Context, username string) (*UserCredential, error)

	// Reload refreshes credentials from the backing store.
	Reload(ctx context.Context) error
}
