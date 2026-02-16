package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleartextAuthenticator_HandleStartup(t *testing.T) {
	auth := &CleartextAuthenticator{ServerVersion: "17.4"}
	session := &Session{State: StateInit}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	challenge, err := auth.HandleStartup(session, cred)
	require.NoError(t, err)
	assert.NotEmpty(t, challenge)
	assert.Equal(t, StateChallengeSent, session.State)
	assert.Equal(t, AuthCleartext, session.AuthMethod)
}

func TestCleartextAuthenticator_HandleResponse_Success(t *testing.T) {
	auth := &CleartextAuthenticator{ServerVersion: "17.4"}
	session := &Session{
		State:      StateChallengeSent,
		AuthMethod: AuthCleartext,
		Username:   "alice",
	}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	msgData := map[string]string{"Password": "secret"}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	require.NoError(t, err)
	assert.True(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateAuthenticated, session.State)
}

func TestCleartextAuthenticator_HandleResponse_WrongPassword(t *testing.T) {
	auth := &CleartextAuthenticator{ServerVersion: "17.4"}
	session := &Session{
		State:      StateChallengeSent,
		AuthMethod: AuthCleartext,
		Username:   "alice",
	}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	msgData := map[string]string{"Password": "wrong"}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateFailed, session.State)
}

func TestCleartextAuthenticator_HandleResponse_EmptyPassword(t *testing.T) {
	auth := &CleartextAuthenticator{ServerVersion: "17.4"}
	session := &Session{
		State:      StateChallengeSent,
		AuthMethod: AuthCleartext,
		Username:   "alice",
	}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	msgData := map[string]string{"Password": ""}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateFailed, session.State)
}
