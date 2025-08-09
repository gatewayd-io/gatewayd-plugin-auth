package plugin

import (
    "context"
    "crypto/md5"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"

    sdkAct "github.com/gatewayd-io/gatewayd-plugin-sdk/act"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	sdkPlugin "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	apiV1 "github.com/gatewayd-io/gatewayd/api/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/jackc/pgx/v5/pgproto3"
    "github.com/spf13/cast"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc"
)

var (
	// TODO: Handle this in a better way
	errorResponse = postgres.ErrorResponse(
		ERROR_MESSAGE,
		ERROR_SEVERITY,
		ERROR_MESSAGE,
		"",
	)
)

type Session struct {
	Username string
	Password string
}

type ConnPair struct {
	ClientLocal  string
	ClientRemote string
	ServerLocal  string
	ServerRemote string
}
type Plugin struct {
	goplugin.GRPCPlugin
	v1.GatewayDPluginServiceServer

	APIClient       apiV1.GatewayDAdminAPIServiceClient
	APIAddress      string
	AuthType        AuthType
	ClientInfo      map[ConnPair]Session
	Logger          hclog.Logger
	Salt            [4]byte
	CredentialStore CredentialStore
    CertAuth        *CertificateAuthenticator
    ScramSessions   map[ConnPair]*ScramSHA256 // Track SCRAM sessions
    Authorizer      *Authorizer
}

type AuthPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Plugin
}

// GRPCServer registers the plugin with the gRPC server.
func (p *AuthPlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) error {
	v1.RegisterGatewayDPluginServiceServer(s, &p.Impl)
	return nil
}

// GRPCClient returns the plugin client.
func (p *AuthPlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return v1.NewGatewayDPluginServiceClient(c), nil
}

// NewTemplatePlugin returns a new instance of the TestPlugin.
func NewTemplatePlugin(impl Plugin) *AuthPlugin {
	return &AuthPlugin{
		NetRPCUnsupportedPlugin: goplugin.NetRPCUnsupportedPlugin{},
		Impl:                    impl,
	}
}

// GetPluginConfig returns the plugin config. This is called by GatewayD
// when the plugin is loaded. The plugin config is used to configure the
// plugin.
func (p *Plugin) GetPluginConfig(
	ctx context.Context, _ *v1.Struct) (*v1.Struct, error) {
	GetPluginConfig.Inc()

	return v1.NewStruct(PluginConfig)
}

// OnTrafficFromClient is called when a request is received by GatewayD from the client.
// This can be used to modify the request or terminate the connection by returning an error
// or a response.
func (p *Plugin) OnTrafficFromClient(ctx context.Context, req *v1.Struct) (*v1.Struct, error) {
	OnTrafficFromClient.Inc()
	req, err := postgres.HandleClientMessage(req, p.Logger)
	if err != nil {
		p.Logger.Debug("Failed to handle client message", "error", err)
	}

	connPair := getConnPair(req)
	if _, exists := p.ClientInfo[connPair]; !exists {
		p.ClientInfo[connPair] = Session{}
	}

	if val, exists := req.Fields[STARTUP_MESSAGE]; exists {
		startupMessageDecoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err != nil {
			p.Logger.Debug("Failed to decode startup message", "error", err)
			return nil, err
		}

        var parameters map[string]string
        var startupMessage map[string]any
        if err := json.Unmarshal(startupMessageDecoded, &startupMessage); err == nil && startupMessage != nil {
            parameters = cast.ToStringMapString(startupMessage["Parameters"])
        } else {
            // Fallback to legacy stringified map format
            legacy := cast.ToStringMap(string(startupMessageDecoded))
            parameters = cast.ToStringMapString(legacy["Parameters"])
        }
		p.Logger.Debug("OnTrafficFromClient", STARTUP_MESSAGE, parameters)

		authInfo := p.ClientInfo[connPair]
		authInfo.Username = parameters[USER]
		p.ClientInfo[connPair] = authInfo

		// Use credential store to validate user
		if p.CredentialStore != nil {
			if _, err := p.CredentialStore.GetCredential(ctx, authInfo.Username); err != nil {
				p.Logger.Debug("OnTrafficFromClient", "msg", "User not found in credential store", "user", authInfo.Username)

				terminate := pgproto3.Terminate{}
				response, err := terminate.Encode(errorResponse)
				if err != nil {
					p.Logger.Debug("Failed to encode terminate response", "error", err)
					return nil, err
				}
				req = p.sendResponse(req, response, true, true)
				return req, nil
			}
		} else {
			// Fallback to hardcoded validation for backwards compatibility
			if p.ClientInfo[connPair].Username != "postgres" {
				p.Logger.Debug("OnTrafficFromClient", "msg", "User is incorrect")

				terminate := pgproto3.Terminate{}
				response, err := terminate.Encode(errorResponse)
				if err != nil {
					p.Logger.Debug("Failed to encode terminate response", "error", err)
					return nil, err
				}
				req = p.sendResponse(req, response, true, true)
				return req, nil
			}
		}

		p.Logger.Debug("OnTrafficFromClient", "msg", "User is valid")

        var response []byte
		switch p.AuthType {
		case CLEARTEXT_PASSWORD:
			p.Logger.Debug("OnTrafficFromClient", "msg", "CleartextPassword")
			authResponse := pgproto3.AuthenticationCleartextPassword{}
            response, err = authResponse.Encode(nil)
			if err != nil {
				p.Logger.Debug("Failed to encode cleartext password", "error", err)
				return nil, err
			}
		case MD5:
			p.Logger.Debug("OnTrafficFromClient", "msg", "MD5")
			authResponse := pgproto3.AuthenticationMD5Password{
				Salt: p.Salt,
			}
			response, err = authResponse.Encode(nil)
			if err != nil {
				p.Logger.Debug("Failed to encode MD5 password", "error", err)
				return nil, err
			}
		case SCRAM_SHA_256:
			p.Logger.Debug("OnTrafficFromClient", "msg", "ScramSHA256")

			if !p.isTLSEnabled(req, connPair) {
				p.Logger.Debug(
					"OnTrafficFromClient", "msg", "TLS is not enabled, cannot use SCRAM-SHA-256")

				terminate := pgproto3.Terminate{}
				response, err := terminate.Encode(errorResponse)
				if err != nil {
					p.Logger.Debug("Failed to encode terminate response", "error", err)
					return nil, err
				}
                    req = p.sendResponse(req, response, true, true)
				return req, nil
			}

			authResponse := pgproto3.AuthenticationSASL{
				AuthMechanisms: []string{"SCRAM-SHA-256"},
			}
			response, err = authResponse.Encode(nil)
			if err != nil {
				p.Logger.Debug("Failed to encode SCRAM-SHA-256 password", "error", err)
				return nil, err
			}
		case CERT:
			p.Logger.Debug("OnTrafficFromClient", "msg", "Certificate authentication")

			if !p.isTLSEnabled(req, connPair) {
				p.Logger.Debug("OnTrafficFromClient", "msg", "TLS is not enabled, cannot use certificate authentication")

				terminate := pgproto3.Terminate{}
				response, err := terminate.Encode(errorResponse)
				if err != nil {
					p.Logger.Debug("Failed to encode terminate response", "error", err)
					return nil, err
				}
				req = p.sendResponse(req, response, true, true)
				return req, nil
			}

			// For certificate authentication, we can authenticate directly here
			if p.CertAuth != nil {
				if cred, err := p.CertAuth.AuthenticateWithCertificate(ctx, req); err != nil {
					p.Logger.Debug("OnTrafficFromClient", "msg", "Certificate authentication failed", "error", err)

					terminate := pgproto3.Terminate{}
					response, err := terminate.Encode(errorResponse)
					if err != nil {
						p.Logger.Debug("Failed to encode terminate response", "error", err)
						return nil, err
					}
					req = p.sendResponse(req, response, true, true)
					return req, nil
				} else {
					p.Logger.Debug("OnTrafficFromClient", "msg", "Certificate authentication successful", "username", cred.Username)

					// Mark as authenticated and proceed to ready state
					p.ClientInfo[connPair] = Session{Username: cred.Username, Password: "cert-auth"}

					// Send authentication success response
					authOK := pgproto3.AuthenticationOk{}
					pStat1 := pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"}
					pStat2 := pgproto3.ParameterStatus{Name: "server_version", Value: "15.4"}
					backendKeyData := pgproto3.BackendKeyData{ProcessID: 12345, SecretKey: 54321}
					readyForQuery := pgproto3.ReadyForQuery{TxStatus: 'I'}

					authOKResp, err := authOK.Encode(nil)
					if err != nil {
						p.Logger.Debug("Failed to encode auth ok", "error", err)
						return nil, err
					}
					pStat2Resp, err := pStat2.Encode(authOKResp)
					if err != nil {
						p.Logger.Debug("Failed to encode parameter status", "error", err)
						return nil, err
					}
					pStat1Resp, err := pStat1.Encode(pStat2Resp)
					if err != nil {
						p.Logger.Debug("Failed to encode parameter status", "error", err)
						return nil, err
					}
					backKeyDataResp, err := backendKeyData.Encode(pStat1Resp)
					if err != nil {
						p.Logger.Debug("Failed to encode backend key data", "error", err)
						return nil, err
					}
					response, err = readyForQuery.Encode(backKeyDataResp)
					if err != nil {
						p.Logger.Debug("Failed to encode ready for query", "error", err)
						return nil, err
					}
                    // do not terminate; allow session to proceed
                    req = p.sendResponse(req, response, false, true)
					return req, nil
				}
			}

			// If no certificate authenticator, fall back to password authentication
			authResponse := pgproto3.AuthenticationCleartextPassword{}
			response, err = authResponse.Encode(nil)
			if err != nil {
				p.Logger.Debug("Failed to encode cleartext password", "error", err)
				return nil, err
			}
		}

        // normal auth challenge; do not terminate connection
        req = p.sendResponse(req, response, false, true)
	}

	// Handle SASL Initial Response (for SCRAM-SHA-256)
    if val, exists := req.Fields[SASL_INITIAL_RESPONSE]; exists {
        saslInitialDecoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err != nil {
			p.Logger.Debug("Failed to decode SASL initial response", "error", err)
			return nil, err
		}

        // Parse JSON { "Mechanism": "SCRAM-SHA-256", "Data": "n,,n=...,r=..." }
        var saslInit map[string]any
        if err := json.Unmarshal(saslInitialDecoded, &saslInit); err != nil {
            p.Logger.Debug("Failed to unmarshal SASL initial response", "error", err)
            errorResp, _ := CreateScramErrorResponse("invalid-initial-response-json")
            req = p.sendResponse(req, errorResp, true, true)
            return req, nil
        }
        dataStr := cast.ToString(saslInit["Data"])
        username, clientNonce, err := ParseScramInitialResponse([]byte(dataStr))
		if err != nil {
			p.Logger.Debug("Failed to parse SCRAM initial response", "error", err)

			errorResp, err := CreateScramErrorResponse("invalid-initial-response")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

		p.Logger.Debug("OnTrafficFromClient", "saslInitialResponse", "username", username)

		// Get user credential from store
		if p.CredentialStore == nil {
			p.Logger.Debug("OnTrafficFromClient", "msg", "No credential store configured")

			errorResp, err := CreateScramErrorResponse("no-credential-store")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

		credential, err := p.CredentialStore.GetCredential(ctx, username)
		if err != nil {
			p.Logger.Debug("OnTrafficFromClient", "msg", "User not found in credential store", "error", err)

			errorResp, err := CreateScramErrorResponse("unknown-user")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

        // Prepare SCRAM session using stored salt/keys from credential
        var saltBytes []byte
        if credential.Salt != "" {
            // salt can be base64 or raw
            if dec, derr := base64.StdEncoding.DecodeString(credential.Salt); derr == nil {
                saltBytes = dec
            } else {
                saltBytes = []byte(credential.Salt)
            }
        }
        // server nonce: generate base64 string deterministically per session
        serverNonce := makeRandomNonce()
        storedKeyBytes, serverKeyBytes := decodeB64(credential.StoredKey), decodeB64(credential.ServerKey)
        scramSession, err := NewScramSHA256Session(
            username,
            saltBytes,
            credential.Iterations,
            serverNonce,
            storedKeyBytes,
            serverKeyBytes,
            credential.Password,
        )
		if err != nil {
			p.Logger.Debug("Failed to create SCRAM session", "error", err)

			errorResp, err := CreateScramErrorResponse("server-error")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

        // Track session for this connection
		if p.ScramSessions == nil {
			p.ScramSessions = make(map[ConnPair]*ScramSHA256)
		}
		p.ScramSessions[connPair] = scramSession

        // The clientFirst message contains client nonce we parsed; ensure the session captures it
        _ = clientNonce
        response, err := scramSession.GenerateServerFirstMessage(string(saslInitialDecoded))
		if err != nil {
			p.Logger.Debug("Failed to generate server first message", "error", err)

			errorResp, err := CreateScramErrorResponse("server-error")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

        req = p.sendResponse(req, response, false, true)
		return req, nil
	}

	// Handle SASL Response (for SCRAM-SHA-256)
    if val, exists := req.Fields[SASL_RESPONSE]; exists {
        saslResponseDecoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err != nil {
			p.Logger.Debug("Failed to decode SASL response", "error", err)
			return nil, err
		}

        // Parse JSON { "Data": "c=...,r=...,p=..." }
        var saslResp map[string]any
        if err := json.Unmarshal(saslResponseDecoded, &saslResp); err != nil {
            p.Logger.Debug("Failed to unmarshal SASL response", "error", err)
            errorResp, _ := CreateScramErrorResponse("invalid-response-json")
            req = p.sendResponse(req, errorResp, true, true)
            return req, nil
        }
        dataStr := cast.ToString(saslResp["Data"])

        // Get SCRAM session for this connection
		scramSession, exists := p.ScramSessions[connPair]
		if !exists {
			p.Logger.Debug("OnTrafficFromClient", "msg", "No SCRAM session found for connection")

			errorResp, err := CreateScramErrorResponse("no-session")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

		// Verify client final message
        response, success, err := scramSession.VerifyClientFinalMessage(dataStr)
		if err != nil {
			p.Logger.Debug("Failed to verify client final message", "error", err)

			errorResp, err := CreateScramErrorResponse("authentication-failed")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

		if !success {
			p.Logger.Debug("OnTrafficFromClient", "msg", "SCRAM authentication failed")

			errorResp, err := CreateScramErrorResponse("authentication-failed")
			if err != nil {
				p.Logger.Debug("Failed to create SCRAM error response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, errorResp, true, true)
			return req, nil
		}

		p.Logger.Debug("OnTrafficFromClient", "msg", "SCRAM authentication successful", "username", scramSession.Username)

		// Clean up session
		delete(p.ScramSessions, connPair)

		// Mark as authenticated
		p.ClientInfo[connPair] = Session{Username: scramSession.Username, Password: "scram-auth"}

        // Send server final message; do not terminate
        req = p.sendResponse(req, response, false, true)
		return req, nil
	}

	if val, exists := req.Fields[PASSWORD_MESSAGE]; exists {
		passwordMessageDecoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err != nil {
			p.Logger.Debug("Failed to decode password message", "error", err)
			return nil, err
		}

		passwordMessage := cast.ToStringMapString(string(passwordMessageDecoded))
		p.Logger.Debug("OnTrafficFromClient", "passwordMessage", passwordMessage)

		authInfo := p.ClientInfo[connPair]
        switch p.AuthType {
		case CLEARTEXT_PASSWORD:
			authInfo.Password = passwordMessage[PASSWORD]
		case MD5:
			// Use credential store if available
			if p.CredentialStore != nil {
				credential, err := p.CredentialStore.GetCredential(ctx, authInfo.Username)
				if err != nil {
					p.Logger.Debug("OnTrafficFromClient", "msg", "User not found in credential store", "error", err)
					p.ClientInfo[connPair] = Session{} // Reset auth info
					break
				}

				password := credential.Password
				if len(passwordMessage[PASSWORD]) != MD5_PASSWORD_LENGTH {
					p.Logger.Debug("OnTrafficFromClient", "msg", "Password is incorrect")
					p.ClientInfo[connPair] = Session{} // Reset auth info
					break
				}

                hashedPassword := pgMD5Encrypt(password, authInfo.Username, string(p.Salt[:]))
				p.Logger.Debug("OnTrafficFromClient", "hashedPassword", hashedPassword)

				if hashedPassword == passwordMessage[PASSWORD] {
					authInfo.Password = password
				}
			} else {
				// Fallback to hardcoded validation
				password := "postgres"
				if len(passwordMessage[PASSWORD]) != MD5_PASSWORD_LENGTH {
					p.Logger.Debug("OnTrafficFromClient", "msg", "Password is incorrect")
					p.ClientInfo[connPair] = Session{} // Reset auth info
					break
				}

                hashedPassword := pgMD5Encrypt(password, authInfo.Username, string(p.Salt[:]))
				p.Logger.Debug("OnTrafficFromClient", "hashedPassword", hashedPassword)

				if hashedPassword == passwordMessage[PASSWORD] {
					authInfo.Password = password
				}
			}
		case SCRAM_SHA_256:
			if !p.isTLSEnabled(req, connPair) {
				break
			}
			if passwordMessage[PASSWORD] == "SCRAM-SHA-256" {
				p.Logger.Debug("OnTrafficFromClient", "msg", "SCRAM-SHA-256 is not implemented yet")
				authInfo.Password = passwordMessage[PASSWORD]
				break
			}
			// TODO: Implement SCRAM-SHA-256
			p.Logger.Debug("OnTrafficFromClient", "msg", "SCRAM-SHA-256 is not implemented yet")
		case CERT:
			// Certificate authentication is handled in startup message
			p.Logger.Debug("OnTrafficFromClient", "msg", "Certificate authentication should be handled in startup message")
		}
		p.ClientInfo[connPair] = authInfo

		// Validate credentials
		var isValid bool
		if p.CredentialStore != nil {
			switch p.AuthType {
			case CLEARTEXT_PASSWORD:
				if _, err := p.CredentialStore.ValidateCredential(ctx, authInfo.Username, authInfo.Password); err == nil {
					isValid = true
				}
			case MD5:
				// MD5 validation is done above
				isValid = authInfo.Password != ""
			case CERT:
				// Certificate validation is done in startup message
				isValid = authInfo.Password == "cert-auth"
			}
		} else {
			// Fallback to hardcoded validation
			isValid = authInfo.Username == "postgres" && (authInfo.Password == "postgres" || authInfo.Password == "SCRAM-SHA-256" || authInfo.Password == "cert-auth")
		}

        if isValid {
            // Authorization check (optional)
            if p.Authorizer != nil {
                dbName := ""
                if val, ok := req.Fields[STARTUP_MESSAGE]; ok {
                    if sm, err := base64.StdEncoding.DecodeString(val.GetStringValue()); err == nil {
                        m := cast.ToStringMap(string(sm))
                        params := cast.ToStringMapString(m["Parameters"])
                        dbName = params["database"]
                    }
                }
                allowed, reason := p.Authorizer.AuthorizeConnect(ctx, authInfo.Username, dbName)
                if !allowed {
                    p.Logger.Debug("Authorization denied", "user", authInfo.Username, "db", dbName, "reason", reason)
                    terminate := pgproto3.Terminate{}
                    response, _ := terminate.Encode(errorResponse)
                    req = p.sendResponse(req, response, true, true)
                    return req, nil
                }
            }
			p.Logger.Debug("OnTrafficFromClient", "msg", "Username/Password is correct")
			p.ClientInfo[connPair] = Session{} // Reset auth info

			authOK := pgproto3.AuthenticationOk{}
			pStat1 := pgproto3.ParameterStatus{
				Name:  "client_encoding",
				Value: "UTF8",
			}
			pStat2 := pgproto3.ParameterStatus{
				Name:  "server_version",
				Value: "15.4",
			}
			backendKeyData := pgproto3.BackendKeyData{
				ProcessID: 12345,
				SecretKey: 54321,
			}
			readyForQuery := pgproto3.ReadyForQuery{TxStatus: 'I'}
			authOKResp, err := authOK.Encode(nil)
			if err != nil {
				p.Logger.Debug("Failed to encode auth ok", "error", err)
				return nil, err
			}
			pStat2Resp, err := pStat2.Encode(authOKResp)
			if err != nil {
				p.Logger.Debug("Failed to encode parameter status", "error", err)
				return nil, err
			}
			pStat1Resp, err := pStat1.Encode(pStat2Resp)
			if err != nil {
				p.Logger.Debug("Failed to encode parameter status", "error", err)
				return nil, err
			}
			backKeyDataResp, err := backendKeyData.Encode(pStat1Resp)
			if err != nil {
				p.Logger.Debug("Failed to encode backend key data", "error", err)
				return nil, err
			}
			response, err := readyForQuery.Encode(backKeyDataResp)
			if err != nil {
				p.Logger.Debug("Failed to encode ready for query", "error", err)
				return nil, err
			}
            // Successful auth; do not terminate here
            req = p.sendResponse(req, response, false, true)
		} else {
			p.Logger.Debug("OnTrafficFromClient", "msg", "Username/Password is incorrect")
			p.ClientInfo[connPair] = Session{} // Reset auth info

			terminate := pgproto3.Terminate{}
			response, err := terminate.Encode(errorResponse)
			if err != nil {
				p.Logger.Debug("Failed to encode terminate response", "error", err)
				return nil, err
			}
            req = p.sendResponse(req, response, true, true)
		}
	} else {
		p.Logger.Debug("OnTrafficFromClient", "msg", "Regular message", "req", req)
	}

	return req, nil
}

func (p *Plugin) OnTrafficFromServer(ctx context.Context, req *v1.Struct) (*v1.Struct, error) {
	OnTrafficFromServer.Inc()
	req, err := postgres.HandleServerMessage(req, p.Logger)
	if err != nil {
		p.Logger.Debug("Failed to handle server message", "error", err)
	}

	p.Logger.Debug("OnTrafficFromServer", "req", req)

	return req, nil
}

// makeRandomNonce creates a base64-encoded 18-byte nonce
func makeRandomNonce() string {
    b := make([]byte, 18)
    if _, err := rand.Read(b); err != nil {
        // fallback to fixed value (only for non-production/testing)
        return base64.StdEncoding.EncodeToString([]byte("gatewayd-fixed-nonce-123"))
    }
    return base64.StdEncoding.EncodeToString(b)
}

// decodeB64 parses base64-encoded string; returns empty slice if input empty/invalid
func decodeB64(s string) []byte {
    if s == "" {
        return nil
    }
    if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
        return dec
    }
    return nil
}

func getConnPair(req *v1.Struct) ConnPair {
	var connPair ConnPair

	if val, exists := req.Fields["client"]; exists {
		client := cast.ToStringMap(val.GetStringValue())
		connPair.ClientLocal = cast.ToString(client["local"])
		connPair.ClientRemote = cast.ToString(client["remote"])
	}

	if val, exists := req.Fields["server"]; exists {
		server := cast.ToStringMap(val.GetStringValue())
		connPair.ServerLocal = cast.ToString(server["local"])
		connPair.ServerRemote = cast.ToString(server["local"])
	}

	return connPair
}

// md5Hash computes the MD5 checksum and returns it as a hex string.
func md5Hash(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// pgMD5Encrypt computes the PostgreSQL-style MD5 checksum for authentication.
// The format is: md5(md5(password + username) + salt).
// concat('md5', md5(concat(md5(concat(password, username)), random-salt)))
// https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-START-UP
func pgMD5Encrypt(username, password, salt string) string {
	// First hash: md5(password + username)
	intermediateHash := md5Hash(password + username)

	// Second hash: md5(intermediateHash + salt)
	finalHash := md5Hash(intermediateHash + salt)

	return "md5" + finalHash
}

// TODO: refactor this to parameterize the signals
func (p *Plugin) sendResponse(
	req *v1.Struct, response []byte, terminate, log bool,
) *v1.Struct {
	signals := []any{}
	if terminate {
		signals = append(signals, sdkAct.Terminate().ToMap())
	}
	if log {
		signals = append(signals,
			sdkAct.Log("info", "Returning response from the auth plugin", map[string]any{
				"plugin": PluginID.GetName(),
			}).ToMap(),
		)
	}

	if len(signals) == 0 {
		// No signals to send, so just return the response.
		req.Fields["response"] = v1.NewBytesValue(response)
		return req
	}

	signalsList, err := v1.NewList(signals)
	if err != nil {
		// This should never happen, but log the error just in case.
		p.Logger.Error("Failed to create signals", "error", err)
	} else {
		// Return the cached response.
		req.Fields[sdkAct.Signals] = v1.NewListValue(signalsList)
		req.Fields["response"] = v1.NewBytesValue(response)
	}

	return req
}

func (p *Plugin) isTLSEnabled(req *v1.Struct, connPair ConnPair) bool {
	client := cast.ToStringMap(sdkPlugin.GetAttr(req, "client", ""))
	if client == nil {
		p.Logger.Debug("OnTrafficFromClient", "msg", "Failed to get client info")
		p.ClientInfo[connPair] = Session{} // Reset auth info
		return false
	}
	p.Logger.Debug("OnTrafficFromClient", "client", client)

	// The local address is the address that GatewayD is listening on.
	localAddr, exists := client["local"]
	if !exists || cast.ToString(localAddr) == "" {
		p.Logger.Debug("OnTrafficFromClient", "msg", "Failed to get local client info")
		p.ClientInfo[connPair] = Session{} // Reset auth info
		return false
	}
	p.Logger.Debug("OnTrafficFromClient", "client.local", client["local"])

	serverConfig := p.filterServers(cast.ToString(localAddr))
	p.Logger.Debug("OnTrafficFromClient", "serverConfig", serverConfig)
	if len(serverConfig) == 0 || !serverConfig[maps.Keys(serverConfig)[0]].IsTLSEnabled {
		p.ClientInfo[connPair] = Session{} // Reset auth info
		return false
	}

	return true
}
