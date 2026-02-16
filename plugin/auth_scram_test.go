package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xdg-go/scram"
)

func TestScramAuthenticator_HandleStartup(t *testing.T) {
	auth := &ScramAuthenticator{ServerVersion: "17.4"}
	session := &Session{State: StateInit}
	cred := &UserCredential{Username: "alice", Password: "secret"}

	challenge, err := auth.HandleStartup(session, cred)
	require.NoError(t, err)
	assert.NotEmpty(t, challenge)
	assert.Equal(t, StateChallengeSent, session.State)
	assert.Equal(t, AuthScramSHA256, session.AuthMethod)
	assert.NotNil(t, session.ScramState)
}

func TestScramAuthenticator_FullHandshake(t *testing.T) {
	auth := &ScramAuthenticator{ServerVersion: "17.4"}
	cred := &UserCredential{Username: "alice", Password: "s3cret"}

	// Step 1: Startup -> SASL challenge
	session := &Session{State: StateInit}
	_, err := auth.HandleStartup(session, cred)
	require.NoError(t, err)
	assert.Equal(t, StateChallengeSent, session.State)

	// Step 2: Client-first message
	// Create a SCRAM client to generate the client-first message.
	client, err := scram.SHA256.NewClient(cred.Username, cred.Password, "")
	require.NoError(t, err)
	clientConv := client.NewConversation()
	clientFirst, err := clientConv.Step("")
	require.NoError(t, err)

	// Send as Data field in the message data.
	msgData := map[string]string{"Data": clientFirst}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	require.NoError(t, err)
	assert.False(t, authenticated) // Should be in SCRAM_CONTINUE state
	assert.NotEmpty(t, response)
	assert.Equal(t, StateScramContinue, session.State)

	// Step 3: Client-final message
	// Extract the server-first message from the response to feed into client conversation.
	serverFirst := string(session.ScramState.ServerFirstMsg)
	clientFinal, err := clientConv.Step(serverFirst)
	require.NoError(t, err)

	msgData = map[string]string{"Data": clientFinal}
	response, authenticated, err = auth.HandleResponse(session, cred, msgData)
	require.NoError(t, err)
	assert.True(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateAuthenticated, session.State)
}

func TestScramAuthenticator_WrongPassword(t *testing.T) {
	auth := &ScramAuthenticator{ServerVersion: "17.4"}
	cred := &UserCredential{Username: "alice", Password: "correct_password"}

	// Step 1: Startup
	session := &Session{State: StateInit}
	_, err := auth.HandleStartup(session, cred)
	require.NoError(t, err)

	// Step 2: Client-first with wrong password
	wrongClient, err := scram.SHA256.NewClient(cred.Username, "wrong_password", "")
	require.NoError(t, err)
	wrongConv := wrongClient.NewConversation()
	clientFirst, err := wrongConv.Step("")
	require.NoError(t, err)

	msgData := map[string]string{"Data": clientFirst}
	response, authenticated, err := auth.HandleResponse(session, cred, msgData)
	require.NoError(t, err)
	assert.False(t, authenticated) // Still in SCRAM_CONTINUE
	assert.NotEmpty(t, response)

	// Step 3: Client-final with wrong password
	serverFirst := string(session.ScramState.ServerFirstMsg)
	clientFinal, err := wrongConv.Step(serverFirst)
	require.NoError(t, err)

	msgData = map[string]string{"Data": clientFinal}
	response, authenticated, err = auth.HandleResponse(session, cred, msgData)
	assert.Error(t, err) // SCRAM verification should fail
	assert.False(t, authenticated)
	assert.NotEmpty(t, response)
	assert.Equal(t, StateFailed, session.State)
}
