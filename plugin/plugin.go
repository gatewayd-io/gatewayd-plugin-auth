package plugin

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"

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

var errorResponse = pgproto3.ErrorResponse{
	Severity: "ERROR",
	Code:     "28P01",
	Message:  "password authentication failed",
}

type AuthInfo struct {
	Username string
	Password string
}

type ConnPair struct {
	Client struct {
		Local  string
		Remote string
	}
	Server struct {
		Local  string
		Remote string
	}
}
type Plugin struct {
	goplugin.GRPCPlugin
	v1.GatewayDPluginServiceServer

	APIClient  apiV1.GatewayDAdminAPIServiceClient
	APIAddress string
	AuthType   AuthType
	ClientInfo map[ConnPair]AuthInfo
	Logger     hclog.Logger
	Salt       [4]byte
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
		p.Logger.Info("Failed to handle client message", "error", err)
	}

	connPair := GetConnPair(req)
	if _, exists := p.ClientInfo[connPair]; !exists {
		p.ClientInfo[connPair] = AuthInfo{}
	}

	if val, exists := req.Fields["startupMessage"]; exists {
		startupMessageDecoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err != nil {
			p.Logger.Info("Failed to decode startup message", "error", err)
			return nil, err
		}

		startupMessage := cast.ToStringMap(string(startupMessageDecoded))
		parameters := cast.ToStringMapString(startupMessage["Parameters"])
		p.Logger.Info("OnTrafficFromClient", "startupMessage", parameters)

		authInfo := p.ClientInfo[connPair]
		authInfo.Username = parameters["user"]
		p.ClientInfo[connPair] = authInfo

		if p.ClientInfo[connPair].Username == "postgres" {
			p.Logger.Info("OnTrafficFromClient", "msg", "User is correct")

			var response []byte
			switch p.AuthType {
			case CLEARTEXTPASSWORD:
				p.Logger.Info("OnTrafficFromClient", "msg", "CleartextPassword")
				authResponse := pgproto3.AuthenticationCleartextPassword{}
				response, err = authResponse.Encode(nil)
				if err != nil {
					p.Logger.Info("Failed to encode cleartext password", "error", err)
					return nil, err
				}
			case MD5:
				p.Logger.Info("OnTrafficFromClient", "msg", "MD5")
				authResponse := pgproto3.AuthenticationMD5Password{
					Salt: p.Salt,
				}
				response, err = authResponse.Encode(nil)
				if err != nil {
					p.Logger.Info("Failed to encode MD5 password", "error", err)
					return nil, err
				}
			case SCRAMSHA256:
				p.Logger.Info("OnTrafficFromClient", "msg", "ScramSHA256")
				authResponse := pgproto3.AuthenticationSASL{
					AuthMechanisms: []string{"SCRAM-SHA-256"},
				}
				response, err = authResponse.Encode(nil)
				if err != nil {
					p.Logger.Info("Failed to encode SCRAM-SHA-256 password", "error", err)
					return nil, err
				}
			}

			req = p.sendResponse(req, response, true, true)
		} else {
			p.Logger.Info("OnTrafficFromClient", "msg", "User is incorrect")

			terminate := pgproto3.Terminate{}
			errResp, err := errorResponse.Encode(nil)
			if err != nil {
				p.Logger.Info("Failed to encode error response", "error", err)
				return nil, err
			}
			response, err := terminate.Encode(errResp)
			if err != nil {
				p.Logger.Info("Failed to encode terminate response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, response, true, true)
		}
	} else if val, exists := req.Fields["passwordMessage"]; exists {
		passwordMessageDecoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err != nil {
			p.Logger.Info("Failed to decode password message", "error", err)
			return nil, err
		}

		passwordMessage := cast.ToStringMapString(string(passwordMessageDecoded))
		p.Logger.Info("OnTrafficFromClient", "passwordMessage", passwordMessage)

		authInfo := p.ClientInfo[connPair]
		switch p.AuthType {
		case CLEARTEXTPASSWORD:
			authInfo.Password = passwordMessage["Password"]
		case MD5:
			password := "postgres"
			if len(passwordMessage["Password"]) != MD5_PASSWORD_LENGTH {
				p.Logger.Info("OnTrafficFromClient", "msg", "Password is incorrect")
				p.ClientInfo[connPair] = AuthInfo{} // Reset auth info
				break
			}

			hashedPassword := pgMD5Encrypt(password, authInfo.Username, string(p.Salt[:]))
			p.Logger.Info("OnTrafficFromClient", "hashedPassword", hashedPassword)

			if hashedPassword == passwordMessage["Password"] {
				authInfo.Password = password
			}
		case SCRAMSHA256:
			server := cast.ToStringMapString(sdkPlugin.GetAttr(req, "server", ""))
			serverConfig := p.filterServers(server["network"], server["address"])
			if len(serverConfig) == 0 {
				p.Logger.Info("OnTrafficFromClient", "msg", "Failed to get server config")
				p.ClientInfo[connPair] = AuthInfo{} // Reset auth info
				break
			}
			if !serverConfig[maps.Keys(serverConfig)[0]].IsTLSEnabled {
				p.Logger.Info("OnTrafficFromClient", "msg", "TLS is not enabled, cannot use SCRAM-SHA-256")
				p.ClientInfo[connPair] = AuthInfo{} // Reset auth info
				break
			}
			if passwordMessage["Password"] == "SCRAM-SHA-256" {
				p.Logger.Info("OnTrafficFromClient", "msg", "SCRAM-SHA-256 is not implemented yet")
				authInfo.Password = passwordMessage["Password"]
				break
			}
			// TODO: Implement SCRAM-SHA-256
			p.Logger.Info("OnTrafficFromClient", "msg", "SCRAM-SHA-256 is not implemented yet")
		}
		p.ClientInfo[connPair] = authInfo

		if p.ClientInfo[connPair].Username == "postgres" && (p.ClientInfo[connPair].Password == "postgres" || p.ClientInfo[connPair].Password == "SCRAM-SHA-256") {
			p.Logger.Info("OnTrafficFromClient", "msg", "Username/Password is correct")
			p.ClientInfo[connPair] = AuthInfo{} // Reset auth info

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
				p.Logger.Info("Failed to encode auth ok", "error", err)
				return nil, err
			}
			pStat2Resp, err := pStat2.Encode(authOKResp)
			if err != nil {
				p.Logger.Info("Failed to encode parameter status", "error", err)
				return nil, err
			}
			pStat1Resp, err := pStat1.Encode(pStat2Resp)
			if err != nil {
				p.Logger.Info("Failed to encode parameter status", "error", err)
				return nil, err
			}
			backKeyDataResp, err := backendKeyData.Encode(pStat1Resp)
			if err != nil {
				p.Logger.Info("Failed to encode backend key data", "error", err)
				return nil, err
			}
			response, err := readyForQuery.Encode(backKeyDataResp)
			if err != nil {
				p.Logger.Info("Failed to encode ready for query", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, response, true, true)
		} else {
			p.Logger.Info("OnTrafficFromClient", "msg", "Username/Password is incorrect")
			p.ClientInfo[connPair] = AuthInfo{} // Reset auth info

			terminate := pgproto3.Terminate{}
			errResp, err := errorResponse.Encode(nil)
			if err != nil {
				p.Logger.Info("Failed to encode error response", "error", err)
				return nil, err
			}
			response, err := terminate.Encode(errResp)
			if err != nil {
				p.Logger.Info("Failed to encode terminate response", "error", err)
				return nil, err
			}
			req = p.sendResponse(req, response, true, true)
		}
	} else {
		p.Logger.Info("OnTrafficFromClient", "msg", "Regular message", "req", req)
	}

	return req, nil
}

func (p *Plugin) OnTrafficFromServer(ctx context.Context, req *v1.Struct) (*v1.Struct, error) {
	OnTrafficFromServer.Inc()
	req, err := postgres.HandleServerMessage(req, p.Logger)
	if err != nil {
		p.Logger.Info("Failed to handle server message", "error", err)
	}

	p.Logger.Debug("OnTrafficFromServer", "req", req)

	return req, nil
}

func GetConnPair(req *v1.Struct) ConnPair {
	var connPair ConnPair

	if val, exists := req.Fields["client"]; exists {
		client := cast.ToStringMap(val.GetStringValue())
		connPair.Client.Local = cast.ToString(client["local"])
		connPair.Client.Remote = cast.ToString(client["remote"])
	}

	if val, exists := req.Fields["server"]; exists {
		server := cast.ToStringMap(val.GetStringValue())
		connPair.Server.Local = cast.ToString(server["local"])
		connPair.Server.Remote = cast.ToString(server["local"])
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

func (p *Plugin) sendResponse(
	req *v1.Struct, response []byte, terminate bool, log bool,
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
