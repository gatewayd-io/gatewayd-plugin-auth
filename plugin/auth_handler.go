package plugin

import (
	"context"
	"encoding/base64"
	"fmt"

	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cast"
)

// AuthHandler is the central auth state machine dispatcher.
// It coordinates credential lookup, authenticator selection, and session management.
type AuthHandler struct {
	Logger         hclog.Logger
	Sessions       *SessionManager
	CredStore      CredentialStore
	Authenticators map[AuthType]Authenticator
	Authorizer     *Authorizer
	DefaultAuth    AuthType
}

// NewAuthHandler creates a new AuthHandler with the given components.
func NewAuthHandler(
	logger hclog.Logger,
	sessions *SessionManager,
	credStore CredentialStore,
	authorizer *Authorizer,
	defaultAuth AuthType,
	serverVersion string,
) *AuthHandler {
	authenticators := map[AuthType]Authenticator{
		AuthCleartext:   &CleartextAuthenticator{ServerVersion: serverVersion},
		AuthMD5:         &MD5Authenticator{ServerVersion: serverVersion},
		AuthScramSHA256: &ScramAuthenticator{ServerVersion: serverVersion},
	}

	return &AuthHandler{
		Logger:         logger,
		Sessions:       sessions,
		CredStore:      credStore,
		Authenticators: authenticators,
		Authorizer:     authorizer,
		DefaultAuth:    defaultAuth,
	}
}

// HandleTrafficFromClient processes a client message through the auth state machine.
// Returns the (possibly modified) request struct.
func (h *AuthHandler) HandleTrafficFromClient(ctx context.Context, req *v1.Struct) (*v1.Struct, error) {
	clientRemote := getClientRemote(req)
	if clientRemote == "" {
		h.Logger.Warn("No client remote address in request")
		return req, nil
	}

	session := h.Sessions.GetOrCreate(clientRemote)

	// If already authenticated, check authorization for queries.
	if session.State == StateAuthenticated {
		return h.handleAuthorizedTraffic(ctx, req, session)
	}

	fields := req.GetFields()

	// Handle startup message (initial connection).
	if val, exists := fields[FieldStartupMessage]; exists {
		return h.handleStartupMessage(ctx, req, session, val.GetStringValue())
	}

	// Handle password message (cleartext or MD5 response).
	if val, exists := fields[FieldPasswordMessage]; exists {
		return h.handlePasswordMessage(ctx, req, session, clientRemote, val.GetStringValue())
	}

	// Handle SASL initial response (SCRAM client-first).
	if val, exists := fields[FieldSASLInitialResponse]; exists {
		return h.handleSASLInitialResponse(ctx, req, session, clientRemote, val.GetStringValue())
	}

	// Handle SASL response (SCRAM client-final).
	if val, exists := fields[FieldSASLResponse]; exists {
		return h.handleSASLResponse(ctx, req, session, clientRemote, val.GetStringValue())
	}

	// Not an auth-related message and not authenticated yet -- this shouldn't happen
	// in normal flow. Pass through (GatewayD may have its own handling).
	return req, nil
}

// handleStartupMessage processes a PostgreSQL StartupMessage.
func (h *AuthHandler) handleStartupMessage(
	ctx context.Context, req *v1.Struct, session *Session, encodedMsg string,
) (*v1.Struct, error) {
	decoded, err := DecodeBase64Field(encodedMsg)
	if err != nil {
		h.Logger.Error("Failed to decode startup message", "error", err)
		return h.terminateWithAuthFail(req, "invalid startup message")
	}

	user, database, err := ParseStartupParams(decoded)
	if err != nil {
		h.Logger.Error("Failed to parse startup parameters", "error", err)
		return h.terminateWithAuthFail(req, "invalid startup parameters")
	}

	h.Logger.Debug("Startup message", "user", user, "database", database)

	// Look up user in credential store.
	cred, err := h.CredStore.LookupUser(ctx, user)
	if err != nil {
		h.Logger.Info("User lookup failed", "user", user, "error", err)
		return h.terminateWithAuthFail(req,
			fmt.Sprintf("password authentication failed for user %q", user))
	}

	// Check if database is allowed.
	if !cred.IsDatabaseAllowed(database) {
		h.Logger.Info("Database not allowed", "user", user, "database", database)
		return h.terminateWithAuthFail(req,
			fmt.Sprintf("user %q is not allowed to connect to database %q", user, database))
	}

	session.Username = user
	session.Database = database
	session.Roles = cred.Roles

	// Select auth method.
	authMethod := h.selectAuthMethod(cred)
	authenticator, ok := h.Authenticators[authMethod]
	if !ok {
		h.Logger.Error("No authenticator for method", "method", authMethod)
		return h.terminateWithAuthFail(req, "unsupported auth method")
	}

	// Send auth challenge.
	challenge, err := authenticator.HandleStartup(session, cred)
	if err != nil {
		h.Logger.Error("Failed to create auth challenge", "error", err)
		return h.terminateWithAuthFail(req, "internal error during authentication")
	}

	return sendTerminateResponse(req, challenge, h.Logger)
}

// handlePasswordMessage processes a PasswordMessage (cleartext or MD5 response).
func (h *AuthHandler) handlePasswordMessage(
	ctx context.Context, req *v1.Struct, session *Session, clientRemote, encodedMsg string,
) (*v1.Struct, error) {
	if session.State != StateChallengeSent {
		h.Logger.Warn("Password message in unexpected state", "state", session.State)
		return h.terminateWithAuthFail(req, "unexpected password message")
	}

	decoded, err := DecodeBase64Field(encodedMsg)
	if err != nil {
		h.Logger.Error("Failed to decode password message", "error", err)
		return h.terminateWithAuthFail(req, "invalid password message")
	}

	msgData := ParsePasswordMessage(decoded)

	cred, err := h.CredStore.LookupUser(ctx, session.Username)
	if err != nil {
		h.Logger.Error("User lookup failed during password validation", "error", err)
		h.Sessions.Remove(clientRemote)
		return h.terminateWithAuthFail(req, "authentication failed")
	}

	authenticator, ok := h.Authenticators[session.AuthMethod]
	if !ok {
		h.Sessions.Remove(clientRemote)
		return h.terminateWithAuthFail(req, "unsupported auth method")
	}

	response, authenticated, err := authenticator.HandleResponse(session, cred, msgData)
	if err != nil {
		h.Logger.Debug("Auth response handling error", "error", err)
	}

	if !authenticated {
		h.Logger.Info("Authentication failed", "user", session.Username)
		h.Sessions.Remove(clientRemote)
		AuthFailures.Inc()
		return sendTerminateResponse(req, response, h.Logger)
	}

	h.Logger.Info("Authentication successful", "user", session.Username)
	AuthSuccesses.Inc()
	return sendTerminateResponse(req, response, h.Logger)
}

// handleSASLInitialResponse processes a SASLInitialResponse (SCRAM client-first).
func (h *AuthHandler) handleSASLInitialResponse(
	ctx context.Context, req *v1.Struct, session *Session, clientRemote, encodedMsg string,
) (*v1.Struct, error) {
	if session.State != StateChallengeSent || session.AuthMethod != AuthScramSHA256 {
		h.Logger.Warn("SASL initial response in unexpected state")
		return h.terminateWithAuthFail(req, "unexpected SASL message")
	}

	decoded, err := DecodeBase64Field(encodedMsg)
	if err != nil {
		h.Logger.Error("Failed to decode SASL initial response", "error", err)
		return h.terminateWithAuthFail(req, "invalid SASL message")
	}

	msgData := cast.ToStringMapString(string(decoded))

	cred, err := h.CredStore.LookupUser(ctx, session.Username)
	if err != nil {
		h.Sessions.Remove(clientRemote)
		return h.terminateWithAuthFail(req, "authentication failed")
	}

	authenticator := h.Authenticators[AuthScramSHA256]
	response, authenticated, err := authenticator.HandleResponse(session, cred, msgData)
	if err != nil {
		h.Logger.Debug("SASL initial response error", "error", err)
	}

	if authenticated {
		// Shouldn't happen at this stage, but handle it.
		AuthSuccesses.Inc()
	}

	return sendTerminateResponse(req, response, h.Logger)
}

// handleSASLResponse processes a SASLResponse (SCRAM client-final).
func (h *AuthHandler) handleSASLResponse(
	ctx context.Context, req *v1.Struct, session *Session, clientRemote, encodedMsg string,
) (*v1.Struct, error) {
	if session.State != StateScramContinue {
		h.Logger.Warn("SASL response in unexpected state")
		return h.terminateWithAuthFail(req, "unexpected SASL message")
	}

	decoded, err := DecodeBase64Field(encodedMsg)
	if err != nil {
		h.Logger.Error("Failed to decode SASL response", "error", err)
		return h.terminateWithAuthFail(req, "invalid SASL message")
	}

	msgData := cast.ToStringMapString(string(decoded))

	cred, err := h.CredStore.LookupUser(ctx, session.Username)
	if err != nil {
		h.Sessions.Remove(clientRemote)
		return h.terminateWithAuthFail(req, "authentication failed")
	}

	authenticator := h.Authenticators[AuthScramSHA256]
	response, authenticated, err := authenticator.HandleResponse(session, cred, msgData)
	if err != nil {
		h.Logger.Debug("SASL response error", "error", err)
	}

	if !authenticated {
		h.Logger.Info("SCRAM authentication failed", "user", session.Username)
		h.Sessions.Remove(clientRemote)
		AuthFailures.Inc()
		return sendTerminateResponse(req, response, h.Logger)
	}

	h.Logger.Info("SCRAM authentication successful", "user", session.Username)
	AuthSuccesses.Inc()
	return sendTerminateResponse(req, response, h.Logger)
}

// handleAuthorizedTraffic checks authorization for an already-authenticated session.
func (h *AuthHandler) handleAuthorizedTraffic(
	_ context.Context, req *v1.Struct, session *Session,
) (*v1.Struct, error) {
	if h.Authorizer == nil {
		// No authorizer configured, pass through.
		return req, nil
	}

	fields := req.GetFields()

	// Check if this is a query message that needs authorization.
	var query string
	if val, exists := fields[FieldQuery]; exists {
		decoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err == nil {
			queryData := cast.ToStringMapString(string(decoded))
			query = queryData["String"]
		}
	}
	if val, exists := fields[FieldParse]; exists && query == "" {
		decoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err == nil {
			parseData := cast.ToStringMapString(string(decoded))
			query = parseData["Query"]
		}
	}

	if query == "" {
		// Not a query message, pass through.
		return req, nil
	}

	allowed, err := h.Authorizer.Authorize(session.Username, session.Database, query)
	if err != nil {
		h.Logger.Error("Authorization check failed", "error", err)
		// Fail open on errors (could also fail closed -- configurable in the future).
		return req, nil
	}

	if !allowed {
		h.Logger.Info("Query denied",
			"user", session.Username,
			"database", session.Database,
			"query", query)
		AuthzDenials.Inc()

		response, buildErr := BuildAccessDeniedResponse(
			fmt.Sprintf("permission denied for user %q", session.Username))
		if buildErr != nil {
			h.Logger.Error("Failed to build access denied response", "error", buildErr)
			return req, nil
		}
		return sendTerminateResponse(req, response, h.Logger)
	}

	return req, nil
}

// selectAuthMethod selects the best auth method for a user.
func (h *AuthHandler) selectAuthMethod(cred *UserCredential) AuthType {
	// If the user supports the default, use it.
	if cred.SupportsAuthMethod(h.DefaultAuth) {
		return h.DefaultAuth
	}
	// Otherwise, use the first method they support.
	if len(cred.AuthMethods) > 0 {
		return AuthType(cred.AuthMethods[0])
	}
	return h.DefaultAuth
}

// terminateWithAuthFail builds and returns an auth failure response.
func (h *AuthHandler) terminateWithAuthFail(req *v1.Struct, detail string) (*v1.Struct, error) {
	response, err := BuildAuthFailResponse(detail)
	if err != nil {
		h.Logger.Error("Failed to build auth fail response", "error", err)
		return req, nil
	}
	return sendTerminateResponse(req, response, h.Logger)
}

// getClientRemote extracts the client's remote address from the request.
// GatewayD passes client info as a nested struct: {"client": {"local": "...", "remote": "..."}}.
func getClientRemote(req *v1.Struct) string {
	val, exists := req.GetFields()["client"]
	if !exists {
		return ""
	}

	// The client field is a StructValue (nested map), not a string.
	if clientStruct := val.GetStructValue(); clientStruct != nil {
		if remote, ok := clientStruct.GetFields()["remote"]; ok {
			return remote.GetStringValue()
		}
	}

	// Fallback: try as a string map (for compatibility).
	clientMap := cast.ToStringMap(val.GetStringValue())
	return cast.ToString(clientMap["remote"])
}
