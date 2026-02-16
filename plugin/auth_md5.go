package plugin

import (
	"crypto/md5" //nolint:gosec // MD5 is required by the PostgreSQL protocol
	"encoding/hex"
	"fmt"

	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
)

// MD5Authenticator implements PostgreSQL MD5 password authentication.
// Each session gets a unique salt generated at challenge time.
type MD5Authenticator struct {
	ServerVersion string
}

// Name returns the auth method name.
func (a *MD5Authenticator) Name() AuthType {
	return AuthMD5
}

// HandleStartup generates a per-connection salt and sends an AuthenticationMD5Password challenge.
func (a *MD5Authenticator) HandleStartup(session *Session, _ *UserCredential) ([]byte, error) {
	salt, err := GenerateSalt(SaltSize)
	if err != nil {
		return nil, fmt.Errorf("generating MD5 salt: %w", err)
	}

	session.Salt = salt
	session.AuthMethod = AuthMD5
	session.State = StateChallengeSent

	return postgres.BuildAuthMD5Challenge(salt)
}

// HandleResponse validates the MD5-hashed password.
// PostgreSQL MD5 format: "md5" + md5(md5(password + username) + salt).
func (a *MD5Authenticator) HandleResponse(
	session *Session, cred *UserCredential, msgData map[string]string,
) ([]byte, bool, error) {
	clientHash := msgData["Password"]

	if len(clientHash) != MD5PasswordLength {
		session.State = StateFailed
		resp, err := BuildAuthFailResponse("invalid MD5 password length")
		return resp, false, err
	}

	expectedHash := pgMD5Hash(cred.Password, cred.Username, session.Salt)

	if clientHash != expectedHash {
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

// pgMD5Hash computes the PostgreSQL-style MD5 hash.
// Format: "md5" + md5(md5(password + username) + salt).
func pgMD5Hash(password, username string, salt [SaltSize]byte) string {
	// First hash: md5(password + username)
	inner := md5.Sum([]byte(password + username)) //nolint:gosec
	innerHex := hex.EncodeToString(inner[:])

	// Second hash: md5(innerHex + salt)
	outer := md5.Sum(append([]byte(innerHex), salt[:]...)) //nolint:gosec
	return "md5" + hex.EncodeToString(outer[:])
}
