package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPgMD5Hash(t *testing.T) {
	// Known PostgreSQL MD5 hash values.
	// md5(md5("postgres" + "postgres") + salt)
	salt := [4]byte{0x01, 0x02, 0x03, 0x04}
	hash := pgMD5Hash("postgres", "postgres", salt)

	assert.Equal(t, MD5PasswordLength, len(hash))
	assert.True(t, len(hash) > 3 && hash[:3] == "md5")
}

func TestMD5Authenticator_HandleStartup(t *testing.T) {
	auth := &MD5Authenticator{ServerVersion: "17.4"}
	session := &Session{State: StateInit}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	challenge, err := auth.HandleStartup(session, cred)
	require.NoError(t, err)
	assert.NotEmpty(t, challenge)
	assert.Equal(t, StateChallengeSent, session.State)
	assert.Equal(t, AuthMD5, session.AuthMethod)
	// Salt should be set.
	assert.NotEqual(t, [4]byte{}, session.Salt)
}

func TestMD5Authenticator_HandleResponse_Success(t *testing.T) {
	auth := &MD5Authenticator{ServerVersion: "17.4"}
	salt := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	session := &Session{
		State:      StateChallengeSent,
		AuthMethod: AuthMD5,
		Username:   "alice",
		Salt:       salt,
	}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	// Compute the expected hash.
	expectedHash := pgMD5Hash("secret", "alice", salt)

	msgData := map[string]string{"Password": expectedHash}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	require.NoError(t, err)
	assert.True(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateAuthenticated, session.State)
}

func TestMD5Authenticator_HandleResponse_WrongPassword(t *testing.T) {
	auth := &MD5Authenticator{ServerVersion: "17.4"}
	salt := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	session := &Session{
		State:      StateChallengeSent,
		AuthMethod: AuthMD5,
		Username:   "alice",
		Salt:       salt,
	}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	// Send wrong password hash.
	wrongHash := pgMD5Hash("wrong_password", "alice", salt)
	msgData := map[string]string{"Password": wrongHash}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateFailed, session.State)
}

func TestMD5Authenticator_HandleResponse_InvalidLength(t *testing.T) {
	auth := &MD5Authenticator{ServerVersion: "17.4"}
	session := &Session{
		State:      StateChallengeSent,
		AuthMethod: AuthMD5,
		Username:   "alice",
		Salt:       [4]byte{0x01, 0x02, 0x03, 0x04},
	}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	msgData := map[string]string{"Password": "short"}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateFailed, session.State)
}
