package plugin

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"

    "github.com/jackc/pgx/v5/pgproto3"
    "golang.org/x/crypto/pbkdf2"
)

// ScramSHA256 represents the SCRAM-SHA-256 authentication state
type ScramSHA256 struct {
    Username       string
    // Password is optional; if StoredKey/ServerKey are provided we do not need it
    Password       string
    Salt           []byte
    Iterations     int
    ClientNonce    string
    ServerNonce    string
    ClientFirstMsg string
    ServerFirstMsg string
    ClientFinalMsg string
    ServerFinalMsg string
    StoredKey      []byte
    ServerKey      []byte
}

// NewScramSHA256Session creates a SCRAM-SHA-256 session using stored user parameters.
// Exactly one of (storedKey, serverKey) pair or password must be provided.
func NewScramSHA256Session(username string, salt []byte, iterations int, serverNonceB64 string, storedKey, serverKey []byte, password string) (*ScramSHA256, error) {
    if len(salt) == 0 {
        return nil, errors.New("salt must be provided from credential store")
    }
    if iterations <= 0 {
        iterations = SCRAM_SHA_256_ITERATION_COUNT
    }
    if (len(storedKey) == 0 || len(serverKey) == 0) && password == "" {
        return nil, errors.New("either stored/server keys or password must be provided")
    }

    s := &ScramSHA256{
        Username:    username,
        Password:    password,
        Salt:        salt,
        Iterations:  iterations,
        ServerNonce: serverNonceB64,
        StoredKey:   append([]byte(nil), storedKey...),
        ServerKey:   append([]byte(nil), serverKey...),
    }

    // If stored keys are not provided, derive them from password
    if len(s.StoredKey) == 0 || len(s.ServerKey) == 0 {
        if err := s.computeKeys(); err != nil {
            return nil, fmt.Errorf("failed to compute keys: %v", err)
        }
    }

    return s, nil
}

// computeKeys computes the stored key and server key for SCRAM-SHA-256
func (s *ScramSHA256) computeKeys() error {
	// SaltedPassword := Hi(Normalize(password), salt, iterations)
	saltedPassword := pbkdf2.Key([]byte(s.Password), s.Salt, s.Iterations, SCRAM_SHA_256_KEY_LENGTH, sha256.New)

	// ClientKey := HMAC(SaltedPassword, "Client Key")
	clientKey := hmac.New(sha256.New, saltedPassword)
	clientKey.Write([]byte("Client Key"))
	clientKeyBytes := clientKey.Sum(nil)

	// StoredKey := H(ClientKey)
	storedKeyHash := sha256.Sum256(clientKeyBytes)
	s.StoredKey = storedKeyHash[:]

	// ServerKey := HMAC(SaltedPassword, "Server Key")
	serverKey := hmac.New(sha256.New, saltedPassword)
	serverKey.Write([]byte("Server Key"))
	s.ServerKey = serverKey.Sum(nil)

	return nil
}

// GenerateServerFirstMessage generates the server's first message in SCRAM-SHA-256
func (s *ScramSHA256) GenerateServerFirstMessage(clientFirstMsg string) ([]byte, error) {
	s.ClientFirstMsg = clientFirstMsg

	// Parse client first message: n,,n=username,r=clientNonce
	parts := strings.Split(clientFirstMsg, ",")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid client first message format")
	}

	// Extract client nonce
	for _, part := range parts {
		if strings.HasPrefix(part, "r=") {
			s.ClientNonce = part[2:]
			break
		}
	}

	if s.ClientNonce == "" {
		return nil, fmt.Errorf("client nonce not found in first message")
	}

    // Create combined nonce
    combinedNonce := s.ClientNonce + s.ServerNonce

	// Server first message: r=combinedNonce,s=base64(salt),i=iterations
	s.ServerFirstMsg = fmt.Sprintf("r=%s,s=%s,i=%d",
		combinedNonce,
		base64.StdEncoding.EncodeToString(s.Salt),
		s.Iterations)

	// Create SASL Continue response
	saslContinue := pgproto3.AuthenticationSASLContinue{
		Data: []byte(s.ServerFirstMsg),
	}

	response, err := saslContinue.Encode(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SASL continue: %v", err)
	}

	return response, nil
}

// VerifyClientFinalMessage verifies the client's final message and generates server response
func (s *ScramSHA256) VerifyClientFinalMessage(clientFinalMsg string) ([]byte, bool, error) {
	s.ClientFinalMsg = clientFinalMsg

	// Parse client final message: c=biws,r=combinedNonce,p=clientProof
	parts := strings.Split(clientFinalMsg, ",")
	if len(parts) < 3 {
		return nil, false, fmt.Errorf("invalid client final message format")
	}

	var channelBinding, nonce, clientProofB64 string
	for _, part := range parts {
		if strings.HasPrefix(part, "c=") {
			channelBinding = part[2:]
		} else if strings.HasPrefix(part, "r=") {
			nonce = part[2:]
		} else if strings.HasPrefix(part, "p=") {
			clientProofB64 = part[2:]
		}
	}

	// Verify nonce
	expectedNonce := s.ClientNonce + s.ServerNonce
	if nonce != expectedNonce {
		return nil, false, fmt.Errorf("nonce verification failed")
	}

	// Decode client proof
	clientProof, err := base64.StdEncoding.DecodeString(clientProofB64)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode client proof: %v", err)
	}

    // Verify client proof
    if !s.verifyClientProof(clientProof, channelBinding) {
		return nil, false, fmt.Errorf("client proof verification failed")
	}

	// Generate server final message
	serverSignature := s.computeServerSignature(channelBinding)
	s.ServerFinalMsg = fmt.Sprintf("v=%s", base64.StdEncoding.EncodeToString(serverSignature))

	// Create SASL Final response
	saslFinal := pgproto3.AuthenticationSASLFinal{
		Data: []byte(s.ServerFinalMsg),
	}

	response, err := saslFinal.Encode(nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode SASL final: %v", err)
	}

	return response, true, nil
}

// verifyClientProof verifies the client's proof
func (s *ScramSHA256) verifyClientProof(clientProof []byte, channelBinding string) bool {
	// AuthMessage = ClientFirstMessageBare + "," + ServerFirstMessage + "," + ClientFinalMessageWithoutProof
	clientFirstBare := s.extractClientFirstBare()
	clientFinalWithoutProof := s.extractClientFinalWithoutProof(channelBinding)
	authMessage := clientFirstBare + "," + s.ServerFirstMsg + "," + clientFinalWithoutProof

	// ClientSignature := HMAC(StoredKey, AuthMessage)
	clientSignature := hmac.New(sha256.New, s.StoredKey)
	clientSignature.Write([]byte(authMessage))
	clientSignatureBytes := clientSignature.Sum(nil)

	// ClientKey := ClientSignature XOR ClientProof
	if len(clientProof) != len(clientSignatureBytes) {
		return false
	}

	recoveredClientKey := make([]byte, len(clientProof))
	for i := range clientProof {
		recoveredClientKey[i] = clientProof[i] ^ clientSignatureBytes[i]
	}

	// Verify: StoredKey = H(ClientKey)
	expectedStoredKey := sha256.Sum256(recoveredClientKey)
	return hmac.Equal(s.StoredKey, expectedStoredKey[:])
}

// computeServerSignature computes the server signature for verification
func (s *ScramSHA256) computeServerSignature(channelBinding string) []byte {
	// AuthMessage = ClientFirstMessageBare + "," + ServerFirstMessage + "," + ClientFinalMessageWithoutProof
	clientFirstBare := s.extractClientFirstBare()
	clientFinalWithoutProof := s.extractClientFinalWithoutProof(channelBinding)
	authMessage := clientFirstBare + "," + s.ServerFirstMsg + "," + clientFinalWithoutProof

	// ServerSignature := HMAC(ServerKey, AuthMessage)
	serverSignature := hmac.New(sha256.New, s.ServerKey)
	serverSignature.Write([]byte(authMessage))
	return serverSignature.Sum(nil)
}

// extractClientFirstBare extracts the bare client first message (without GS2 header)
func (s *ScramSHA256) extractClientFirstBare() string {
	// Client first message format: n,,n=username,r=clientNonce
	// We need to remove the GS2 header (n,,) to get the bare message
	parts := strings.SplitN(s.ClientFirstMsg, ",", 3)
	if len(parts) >= 3 {
		return parts[2] // Return everything after the GS2 header
	}
	return s.ClientFirstMsg
}

// extractClientFinalWithoutProof extracts the client final message without the proof
func (s *ScramSHA256) extractClientFinalWithoutProof(channelBinding string) string {
	// Client final message format: c=biws,r=combinedNonce,p=clientProof
	// We need to return: c=biws,r=combinedNonce
	return fmt.Sprintf("c=%s,r=%s", channelBinding, s.ClientNonce+s.ServerNonce)
}

// ParseScramInitialResponse parses the initial SCRAM-SHA-256 response from the client
func ParseScramInitialResponse(data []byte) (username, clientNonce string, err error) {
	// Expected format: n,,n=username,r=clientNonce
	msg := string(data)

	// Split by comma, should have at least 3 parts
	parts := strings.Split(msg, ",")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid SCRAM initial response format")
	}

	// Parse username and client nonce
	for _, part := range parts {
		if strings.HasPrefix(part, "n=") {
			username = part[2:]
		} else if strings.HasPrefix(part, "r=") {
			clientNonce = part[2:]
		}
	}

	if username == "" || clientNonce == "" {
		return "", "", fmt.Errorf("missing username or client nonce in SCRAM initial response")
	}

	return username, clientNonce, nil
}

// CreateScramErrorResponse creates an error response for SCRAM authentication
func CreateScramErrorResponse(errorMsg string) ([]byte, error) {
	saslFinal := pgproto3.AuthenticationSASLFinal{
		Data: []byte(fmt.Sprintf("e=%s", errorMsg)),
	}

	response, err := saslFinal.Encode(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SCRAM error response: %v", err)
	}

	return response, nil
}

// VerifyScramCredentials verifies SCRAM-SHA-256 credentials from credential store
func VerifyScramCredentials(username, password string, salt []byte, iterations int, storedKey, serverKey []byte) bool {
    s := &ScramSHA256{
        Username:  username,
        Password:  password,
        Salt:      salt,
        Iterations: iterations,
    }
    if err := s.computeKeys(); err != nil {
        return false
    }
    return hmac.Equal(s.StoredKey, storedKey) && hmac.Equal(s.ServerKey, serverKey)
}

// GenerateScramCredentials generates SCRAM-SHA-256 credentials for storage
func GenerateScramCredentials(username, password string, iterations int, salt []byte) (saltB64 string, storedKey, serverKey []byte, err error) {
    if iterations <= 0 {
        iterations = SCRAM_SHA_256_ITERATION_COUNT
    }
    if len(salt) == 0 {
        return "", nil, nil, errors.New("salt must be provided")
    }
    s := &ScramSHA256{Username: username, Password: password, Salt: salt, Iterations: iterations}
    if err := s.computeKeys(); err != nil {
        return "", nil, nil, err
    }
    return base64.StdEncoding.EncodeToString(s.Salt), s.StoredKey, s.ServerKey, nil
}
