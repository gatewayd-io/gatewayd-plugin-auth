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

type Plugin struct {
	goplugin.GRPCPlugin
	v1.GatewayDPluginServiceServer
	Logger hclog.Logger
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

	if val, exists := req.Fields["startupMessage"]; exists {
		startupMessageDecoded, err := base64.StdEncoding.DecodeString(val.GetStringValue())
		if err != nil {
			p.Logger.Info("Failed to decode startup message", "error", err)
			return nil, err
		}

		startupMessage := cast.ToStringMap(string(startupMessageDecoded))
		parameters := cast.ToStringMapString(startupMessage["Parameters"])
		p.Logger.Info("OnTrafficFromClient", "startupMessage", parameters)

		if parameters["user"] == "postgres" {
			p.Logger.Info("OnTrafficFromClient", "msg", "User is correct")

			response := pgproto3.AuthenticationCleartextPassword{}
			req.Fields["response"] = v1.NewBytesValue(response.Encode(nil))
			req.Fields["terminate"] = v1.NewBoolValue(true)
		} else {
			p.Logger.Info("OnTrafficFromClient", "msg", "User is incorrect")

			req.Fields["response"] = v1.NewBytesValue(errorResponse.Encode(nil))
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

		if passwordMessage["Password"] == "postgres" {
			p.Logger.Info("OnTrafficFromClient", "msg", "Password is correct")

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
			p.Logger.Info("OnTrafficFromClient", "msg", "Password is incorrect")

			req.Fields["response"] = v1.NewBytesValue(errorResponse.Encode(nil))
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
