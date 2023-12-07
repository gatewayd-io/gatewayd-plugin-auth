package plugin

import (
	"context"
	"encoding/base64"

	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	sdkPlugin "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/spf13/cast"
	"google.golang.org/grpc"
)

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

	if val := req.Fields["startupMessage"]; val != nil {
		startupMessageEncoded := cast.ToString(sdkPlugin.GetAttr(req, "startupMessage", ""))
		if startupMessageEncoded != "" {
			startupMessageDecoded, err := base64.StdEncoding.DecodeString(startupMessageEncoded)
			if err != nil {
				p.Logger.Info("Failed to decode startup message", "error", err)
				return nil, err
			}

			startupMessage := cast.ToStringMapString(string(startupMessageDecoded))
			p.Logger.Info("OnTrafficFromClient", "startupMessage", startupMessage)

			if startupMessage["Type"] == "StartupMessage" {
				p.Logger.Info("OnTrafficFromClient", "User is correct")

				response := pgproto3.AuthenticationCleartextPassword{}
				req.Fields["response"] = v1.NewBytesValue(response.Encode(nil))
				req.Fields["terminate"] = v1.NewBoolValue(true)
			} else {
				p.Logger.Info("OnTrafficFromClient", "User is incorrect")

				response := pgproto3.ErrorResponse{
					Message: "User is incorrect",
				}
				req.Fields["response"] = v1.NewBytesValue(response.Encode(nil))
				req.Fields["terminate"] = v1.NewBoolValue(true)
			}
		}
	} else if val := req.Fields["passwordMessage"]; val != nil {
		passwordMessageEncoded := cast.ToString(sdkPlugin.GetAttr(req, "passwordMessage", ""))
		if passwordMessageEncoded != "" {
			passwordMessageDecoded, err := base64.StdEncoding.DecodeString(passwordMessageEncoded)
			if err != nil {
				p.Logger.Info("Failed to decode password message", "error", err)
				return nil, err
			}

			passwordMessage := cast.ToStringMapString(string(passwordMessageDecoded))
			p.Logger.Info("OnTrafficFromClient", "passwordMessage", passwordMessage)

			if passwordMessage["Password"] == "postgres" {
				p.Logger.Info("OnTrafficFromClient", "Password is correct")

				authOK := pgproto3.AuthenticationOk{}
				readyForQuery := pgproto3.ReadyForQuery{TxStatus: 'I'}
				response := readyForQuery.Encode(authOK.Encode(nil))
				req.Fields["response"] = v1.NewBytesValue(response)
				req.Fields["terminate"] = v1.NewBoolValue(true)
			} else {
				p.Logger.Info("OnTrafficFromClient", "Password is incorrect")

				response := pgproto3.ErrorResponse{
					Message: "Password is incorrect",
				}
				req.Fields["response"] = v1.NewBytesValue(response.Encode(nil))
				req.Fields["terminate"] = v1.NewBoolValue(true)
			}
		}
	} else {
		p.Logger.Info("OnTrafficFromClient", "Regular message")
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
