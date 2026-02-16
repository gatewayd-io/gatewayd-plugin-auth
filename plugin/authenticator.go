package plugin

// Authenticator is the interface for PostgreSQL authentication method implementations.
type Authenticator interface {
	// Name returns the auth method name (e.g., "md5", "scram-sha-256").
	Name() AuthType

	// HandleStartup is called when a StartupMessage arrives for a user.
	// It returns the auth challenge bytes to send to the client.
	HandleStartup(session *Session, cred *UserCredential) ([]byte, error)

	// HandleResponse processes the client's password/SASL response.
	// It returns (response bytes to send, authenticated bool, error).
	// If authenticated is true, response contains AuthOk sequence.
	// If authenticated is false and error is nil, response contains the next
	// challenge (e.g., SASL continue).
	HandleResponse(session *Session, cred *UserCredential, msgData map[string]string) ([]byte, bool, error)
}
