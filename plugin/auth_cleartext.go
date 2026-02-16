package plugin

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
)

// CleartextAuthenticator implements cleartext password authentication.
type CleartextAuthenticator struct {
	ServerVersion string
}

// Name returns the auth method name.
func (a *CleartextAuthenticator) Name() AuthType {
	return AuthCleartext
}

// HandleStartup sends an AuthenticationCleartextPassword challenge.
func (a *CleartextAuthenticator) HandleStartup(session *Session, _ *UserCredential) ([]byte, error) {
	session.AuthMethod = AuthCleartext
	session.State = StateChallengeSent

	return postgres.BuildAuthCleartextChallenge()
}

// HandleResponse validates the cleartext password.
func (a *CleartextAuthenticator) HandleResponse(
	session *Session, cred *UserCredential, msgData map[string]string,
) ([]byte, bool, error) {
	password := msgData["Password"]
	if password == "" {
		session.State = StateFailed
		resp, err := BuildAuthFailResponse("empty password")
		return resp, false, err
	}

	if password != cred.Password {
		session.State = StateFailed
		resp, err := BuildAuthFailResponse(
			fmt.Sprintf("password authentication failed for user %q", session.Username))
		return resp, false, err
	}

	// Authentication successful
	processID, secretKey := generateBackendKeyData()
	resp, err := postgres.BuildAuthOk(a.ServerVersion, processID, secretKey)
	if err != nil {
		return nil, false, fmt.Errorf("building auth ok: %w", err)
	}

	session.State = StateAuthenticated
	return resp, true, nil
}

// generateBackendKeyData generates random process ID and secret key.
func generateBackendKeyData() (uint32, uint32) {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:4]), binary.BigEndian.Uint32(buf[4:])
}
