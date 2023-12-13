package plugin

import (
	"context"
	"encoding/base64"

	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/spf13/cast"
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
	ClientInfo map[ConnPair]AuthInfo
	Logger     hclog.Logger
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

			response := pgproto3.AuthenticationCleartextPassword{}
			req.Fields["response"] = v1.NewBytesValue(response.Encode(nil))
			req.Fields["terminate"] = v1.NewBoolValue(true)
		} else {
			p.Logger.Info("OnTrafficFromClient", "msg", "User is incorrect")

			terminate := pgproto3.Terminate{}
			response := terminate.Encode(errorResponse.Encode(nil))
			req.Fields["response"] = v1.NewBytesValue(response)
			req.Fields["terminate"] = v1.NewBoolValue(true)
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
		authInfo.Password = passwordMessage["Password"]
		p.ClientInfo[connPair] = authInfo

		if p.ClientInfo[connPair].Username == "postgres" && p.ClientInfo[connPair].Password == "postgres" {
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
			response := readyForQuery.Encode(
				backendKeyData.Encode(
					pStat1.Encode(
						pStat2.Encode(
							authOK.Encode(nil),
						),
					),
				),
			)
			req.Fields["response"] = v1.NewBytesValue(response)
			req.Fields["terminate"] = v1.NewBoolValue(true)
		} else {
			p.Logger.Info("OnTrafficFromClient", "msg", "Username/Password is incorrect")
			p.ClientInfo[connPair] = AuthInfo{} // Reset auth info

			terminate := pgproto3.Terminate{}
			response := terminate.Encode(errorResponse.Encode(nil))
			req.Fields["response"] = v1.NewBytesValue(response)
			req.Fields["terminate"] = v1.NewBoolValue(true)
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
