package plugin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	"github.com/xdg-go/scram"
)

// ScramAuthenticator implements SCRAM-SHA-256 authentication (RFC 5802).
// The multi-round handshake requires state across multiple hook invocations.
type ScramAuthenticator struct {
	ServerVersion string
}

// Name returns the auth method name.
func (a *ScramAuthenticator) Name() AuthType {
	return AuthScramSHA256
}

// HandleStartup sends an AuthenticationSASL challenge listing SCRAM-SHA-256.
func (a *ScramAuthenticator) HandleStartup(session *Session, _ *UserCredential) ([]byte, error) {
	session.AuthMethod = AuthScramSHA256
	session.State = StateChallengeSent
	session.ScramState = &ScramServerState{}

	return postgres.BuildAuthSASLChallenge([]string{"SCRAM-SHA-256"})
}

// HandleResponse handles either the SASLInitialResponse (client-first) or the SASLResponse (client-final).
func (a *ScramAuthenticator) HandleResponse(
	session *Session, cred *UserCredential, msgData map[string]string,
) ([]byte, bool, error) {
	switch session.State {
	case StateChallengeSent:
		return a.handleClientFirst(session, cred, msgData)
	case StateScramContinue:
		return a.handleClientFinal(session, cred, msgData)
	default:
		session.State = StateFailed
		resp, err := BuildAuthFailResponse("unexpected SCRAM state")
		return resp, false, err
	}
}

// handleClientFirst processes the SASLInitialResponse (client-first-message).
func (a *ScramAuthenticator) handleClientFirst(
	session *Session, cred *UserCredential, msgData map[string]string,
) ([]byte, bool, error) {
	// Extract the client-first-message from the SASL initial response.
	// The field is a JSON object with "Name" (mechanism), "AuthMechanism" and "Data" (client-first-message bytes).
	clientFirstData, err := extractSASLInitialData(msgData)
	if err != nil {
		session.State = StateFailed
		resp, buildErr := BuildAuthFailResponse("invalid SASL initial response")
		return resp, false, fmt.Errorf("%w: %w", buildErr, err)
	}

	// Create a SCRAM server using the stored password as the credential lookup.
	server, err := scram.SHA256.NewServer(func(username string) (scram.StoredCredentials, error) {
		// Generate stored credentials from the plaintext password.
		client, clientErr := scram.SHA256.NewClient(username, cred.Password, "")
		if clientErr != nil {
			return scram.StoredCredentials{}, clientErr
		}
		return client.GetStoredCredentials(scram.KeyFactors{Iters: 4096}), nil
	})
	if err != nil {
		session.State = StateFailed
		resp, buildErr := BuildAuthFailResponse("SCRAM server creation failed")
		return resp, false, fmt.Errorf("%w: %w", buildErr, err)
	}

	conv := server.NewConversation()
	serverFirst, err := conv.Step(string(clientFirstData))
	if err != nil {
		session.State = StateFailed
		resp, buildErr := BuildAuthFailResponse("SCRAM handshake failed")
		return resp, false, fmt.Errorf("%w: %w", buildErr, err)
	}

	session.ScramState.Conversation = conv
	session.ScramState.ServerFirstMsg = []byte(serverFirst)
	session.State = StateScramContinue

	resp, err := postgres.BuildAuthSASLContinue([]byte(serverFirst))
	return resp, false, err
}

// handleClientFinal processes the SASLResponse (client-final-message).
func (a *ScramAuthenticator) handleClientFinal(
	session *Session, _ *UserCredential, msgData map[string]string,
) ([]byte, bool, error) {
	clientFinalData, err := extractSASLResponseData(msgData)
	if err != nil {
		session.State = StateFailed
		resp, buildErr := BuildAuthFailResponse("invalid SASL response")
		return resp, false, fmt.Errorf("%w: %w", buildErr, err)
	}

	conv, ok := session.ScramState.Conversation.(*scram.ServerConversation)
	if !ok || conv == nil {
		session.State = StateFailed
		resp, buildErr := BuildAuthFailResponse("no active SCRAM conversation")
		return resp, false, buildErr
	}

	serverFinal, err := conv.Step(string(clientFinalData))
	if err != nil {
		session.State = StateFailed
		resp, buildErr := BuildAuthFailResponse(
			fmt.Sprintf("SCRAM authentication failed for user %q", session.Username))
		return resp, false, fmt.Errorf("%w: %w", buildErr, err)
	}

	// Build SASL final + Auth OK
	saslFinal, err := postgres.BuildAuthSASLFinal([]byte(serverFinal))
	if err != nil {
		return nil, false, fmt.Errorf("building SASL final: %w", err)
	}

	processID, secretKey := generateBackendKeyData()
	authOk, err := postgres.BuildAuthOk(a.ServerVersion, processID, secretKey)
	if err != nil {
		return nil, false, fmt.Errorf("building auth ok: %w", err)
	}

	// Combine SASL final + Auth OK sequence
	response := append(saslFinal, authOk...)

	session.State = StateAuthenticated
	session.ScramState = nil // clean up SCRAM state
	return response, true, nil
}

// saslInitialResponseJSON matches the JSON structure from pgproto3.SASLInitialResponse.MarshalJSON().
type saslInitialResponseJSON struct {
	Type          string `json:"Type"`
	AuthMechanism string `json:"AuthMechanism"`
	Data          string `json:"Data"` // base64 encoded
}

// saslResponseJSON matches the JSON structure from pgproto3.SASLResponse.MarshalJSON().
type saslResponseJSON struct {
	Type string `json:"Type"`
	Data string `json:"Data"` // base64 encoded
}

// extractSASLInitialData extracts the client-first-message bytes from the decoded SASL initial response.
func extractSASLInitialData(msgData map[string]string) ([]byte, error) {
	// The msgData comes from cast.ToStringMapString on the JSON of the SASLInitialResponse.
	// We need to get the raw Data field.
	dataStr, ok := msgData["Data"]
	if ok && dataStr != "" {
		// Try base64 decode first
		decoded, err := base64.StdEncoding.DecodeString(dataStr)
		if err == nil {
			return decoded, nil
		}
		// If not base64, return as-is
		return []byte(dataStr), nil
	}

	// Try parsing the whole thing as JSON
	for _, v := range msgData {
		var sasl saslInitialResponseJSON
		if err := json.Unmarshal([]byte(v), &sasl); err == nil && sasl.Data != "" {
			decoded, err := base64.StdEncoding.DecodeString(sasl.Data)
			if err != nil {
				return []byte(sasl.Data), nil
			}
			return decoded, nil
		}
	}

	return nil, fmt.Errorf("no SASL initial data found in message")
}

// extractSASLResponseData extracts the client-final-message bytes from the decoded SASL response.
func extractSASLResponseData(msgData map[string]string) ([]byte, error) {
	dataStr, ok := msgData["Data"]
	if ok && dataStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(dataStr)
		if err == nil {
			return decoded, nil
		}
		return []byte(dataStr), nil
	}

	for _, v := range msgData {
		var sasl saslResponseJSON
		if err := json.Unmarshal([]byte(v), &sasl); err == nil && sasl.Data != "" {
			decoded, err := base64.StdEncoding.DecodeString(sasl.Data)
			if err != nil {
				return []byte(sasl.Data), nil
			}
			return decoded, nil
		}
	}

	return nil, fmt.Errorf("no SASL response data found in message")
}
