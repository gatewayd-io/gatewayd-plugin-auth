package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdkAct "github.com/gatewayd-io/gatewayd-plugin-sdk/act"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupAuthHandler creates a test auth handler with a file credential store.
func setupAuthHandler(t *testing.T) *AuthHandler {
	t.Helper()

	credsYAML := `users:
  - username: testuser
    password: "testpass"
    auth_methods: ["md5", "cleartext", "scram-sha-256"]
    roles: ["admin"]
    databases: ["testdb"]
    enabled: true
  - username: nodbuser
    password: "nodbpass"
    auth_methods: ["md5"]
    roles: ["readonly"]
    databases: ["otherdb"]
    enabled: true
`
	dir := t.TempDir()
	credsPath := filepath.Join(dir, "credentials.yaml")
	require.NoError(t, os.WriteFile(credsPath, []byte(credsYAML), 0o644))

	credStore, err := NewFileCredentialStore(credsPath)
	require.NoError(t, err)

	logger := hclog.NewNullLogger()
	sessions := NewSessionManager(time.Hour)

	return NewAuthHandler(logger, sessions, credStore, nil, AuthMD5, "17.4")
}

// makeStartupReq creates a v1.Struct that simulates a startup message from a client.
func makeStartupReq(user, database, clientRemote string) *v1.Struct {
	startupJSON := map[string]interface{}{
		"ProtocolVersion": 196608,
		"Parameters": map[string]interface{}{
			"user":     user,
			"database": database,
		},
	}
	startupBytes, _ := json.Marshal(startupJSON)
	encoded := base64.StdEncoding.EncodeToString(startupBytes)

	fields := map[string]*v1.Value{
		FieldStartupMessage: v1.NewStringValue(encoded),
		"client":            v1.NewStringValue(`{"local":"127.0.0.1:5432","remote":"` + clientRemote + `"}`),
	}
	return &v1.Struct{Fields: fields}
}

// makePasswordReq creates a v1.Struct that simulates a password message from a client.
func makePasswordReq(password, clientRemote string) *v1.Struct {
	passwordJSON := map[string]interface{}{
		"Password": password,
	}
	passwordBytes, _ := json.Marshal(passwordJSON)
	encoded := base64.StdEncoding.EncodeToString(passwordBytes)

	fields := map[string]*v1.Value{
		FieldPasswordMessage: v1.NewStringValue(encoded),
		"client":             v1.NewStringValue(`{"local":"127.0.0.1:5432","remote":"` + clientRemote + `"}`),
	}
	return &v1.Struct{Fields: fields}
}

func TestAuthHandler_StartupMessage_ValidUser(t *testing.T) {
	handler := setupAuthHandler(t)
	ctx := context.Background()
	clientRemote := "192.168.1.100:54321"

	req := makeStartupReq("testuser", "testdb", clientRemote)
	result, err := handler.HandleTrafficFromClient(ctx, req)
	require.NoError(t, err)

	// Should have a response (auth challenge) and terminate signal.
	assert.NotNil(t, result.Fields[FieldResponse])
	assert.NotNil(t, result.Fields[sdkAct.Signals])

	// Session should be in ChallengeSent state.
	session := handler.Sessions.Get(clientRemote)
	require.NotNil(t, session)
	assert.Equal(t, StateChallengeSent, session.State)
	assert.Equal(t, "testuser", session.Username)
	assert.Equal(t, "testdb", session.Database)
}

func TestAuthHandler_StartupMessage_UnknownUser(t *testing.T) {
	handler := setupAuthHandler(t)
	ctx := context.Background()
	clientRemote := "192.168.1.100:54322"

	req := makeStartupReq("unknown", "testdb", clientRemote)
	result, err := handler.HandleTrafficFromClient(ctx, req)
	require.NoError(t, err)

	// Should have a response (error) and terminate signal.
	assert.NotNil(t, result.Fields[FieldResponse])
	assert.NotNil(t, result.Fields[sdkAct.Signals])
}

func TestAuthHandler_StartupMessage_DatabaseNotAllowed(t *testing.T) {
	handler := setupAuthHandler(t)
	ctx := context.Background()
	clientRemote := "192.168.1.100:54323"

	// nodbuser is only allowed to connect to "otherdb".
	req := makeStartupReq("nodbuser", "testdb", clientRemote)
	result, err := handler.HandleTrafficFromClient(ctx, req)
	require.NoError(t, err)

	// Should have a response (error) and terminate signal.
	assert.NotNil(t, result.Fields[FieldResponse])
	assert.NotNil(t, result.Fields[sdkAct.Signals])
}

func TestAuthHandler_CleartextAuth_FullFlow(t *testing.T) {
	handler := setupAuthHandler(t)
	// Override default auth to cleartext.
	handler.DefaultAuth = AuthCleartext
	ctx := context.Background()
	clientRemote := "192.168.1.100:54324"

	// Step 1: Send startup message.
	startupReq := makeStartupReq("testuser", "testdb", clientRemote)
	result, err := handler.HandleTrafficFromClient(ctx, startupReq)
	require.NoError(t, err)
	assert.NotNil(t, result.Fields[FieldResponse])

	session := handler.Sessions.Get(clientRemote)
	require.NotNil(t, session)
	assert.Equal(t, StateChallengeSent, session.State)
	assert.Equal(t, AuthCleartext, session.AuthMethod)

	// Step 2: Send correct password.
	passwordReq := makePasswordReq("testpass", clientRemote)
	result, err = handler.HandleTrafficFromClient(ctx, passwordReq)
	require.NoError(t, err)
	assert.NotNil(t, result.Fields[FieldResponse])

	session = handler.Sessions.Get(clientRemote)
	require.NotNil(t, session)
	assert.Equal(t, StateAuthenticated, session.State)
}

func TestAuthHandler_CleartextAuth_WrongPassword(t *testing.T) {
	handler := setupAuthHandler(t)
	handler.DefaultAuth = AuthCleartext
	ctx := context.Background()
	clientRemote := "192.168.1.100:54325"

	// Step 1: Send startup message.
	startupReq := makeStartupReq("testuser", "testdb", clientRemote)
	_, err := handler.HandleTrafficFromClient(ctx, startupReq)
	require.NoError(t, err)

	// Step 2: Send wrong password.
	passwordReq := makePasswordReq("wrongpass", clientRemote)
	result, err := handler.HandleTrafficFromClient(ctx, passwordReq)
	require.NoError(t, err)
	assert.NotNil(t, result.Fields[FieldResponse])

	// Session should be removed after failure.
	session := handler.Sessions.Get(clientRemote)
	assert.Nil(t, session)
}

func TestAuthHandler_MD5Auth_FullFlow(t *testing.T) {
	handler := setupAuthHandler(t)
	ctx := context.Background()
	clientRemote := "192.168.1.100:54326"

	// Step 1: Send startup message.
	startupReq := makeStartupReq("testuser", "testdb", clientRemote)
	_, err := handler.HandleTrafficFromClient(ctx, startupReq)
	require.NoError(t, err)

	session := handler.Sessions.Get(clientRemote)
	require.NotNil(t, session)
	assert.Equal(t, StateChallengeSent, session.State)
	assert.Equal(t, AuthMD5, session.AuthMethod)

	// Step 2: Compute correct MD5 hash and send it.
	correctHash := pgMD5Hash("testpass", "testuser", session.Salt)
	passwordReq := makePasswordReq(correctHash, clientRemote)
	result, err := handler.HandleTrafficFromClient(ctx, passwordReq)
	require.NoError(t, err)
	assert.NotNil(t, result.Fields[FieldResponse])

	session = handler.Sessions.Get(clientRemote)
	require.NotNil(t, session)
	assert.Equal(t, StateAuthenticated, session.State)
}

func TestAuthHandler_PassthroughAfterAuth(t *testing.T) {
	handler := setupAuthHandler(t)
	handler.DefaultAuth = AuthCleartext
	ctx := context.Background()
	clientRemote := "192.168.1.100:54327"

	// Authenticate.
	startupReq := makeStartupReq("testuser", "testdb", clientRemote)
	_, err := handler.HandleTrafficFromClient(ctx, startupReq)
	require.NoError(t, err)

	passwordReq := makePasswordReq("testpass", clientRemote)
	_, err = handler.HandleTrafficFromClient(ctx, passwordReq)
	require.NoError(t, err)

	// Subsequent messages should pass through (no authorizer configured).
	queryReq := &v1.Struct{
		Fields: map[string]*v1.Value{
			"client": v1.NewStringValue(`{"local":"127.0.0.1:5432","remote":"` + clientRemote + `"}`),
		},
	}
	result, err := handler.HandleTrafficFromClient(ctx, queryReq)
	require.NoError(t, err)
	// No terminate signal should be set.
	_, hasSignals := result.Fields[sdkAct.Signals]
	assert.False(t, hasSignals)
}
