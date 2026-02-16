package plugin

import (
	"context"

	sdkAct "github.com/gatewayd-io/gatewayd-plugin-sdk/act"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// Plugin is the main auth plugin implementation.
type Plugin struct {
	v1.GatewayDPluginServiceServer

	Logger      hclog.Logger
	AuthHandler *AuthHandler
}

// AuthGRPCPlugin implements the HashiCorp go-plugin GRPCPlugin interface.
type AuthGRPCPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Plugin
}

// GRPCServer registers the plugin with the gRPC server.
func (p *AuthGRPCPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	v1.RegisterGatewayDPluginServiceServer(s, &p.Impl)
	return nil
}

// GRPCClient returns the plugin client.
func (p *AuthGRPCPlugin) GRPCClient(
	_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn,
) (interface{}, error) {
	return v1.NewGatewayDPluginServiceClient(c), nil
}

// GetPluginConfig returns the plugin configuration to GatewayD.
func (p *Plugin) GetPluginConfig(
	_ context.Context, _ *v1.Struct,
) (*v1.Struct, error) {
	GetPluginConfigCalls.Inc()
	return v1.NewStruct(PluginConfig)
}

// OnTrafficFromClient intercepts client traffic for authentication and authorization.
func (p *Plugin) OnTrafficFromClient(
	ctx context.Context, req *v1.Struct,
) (*v1.Struct, error) {
	OnTrafficFromClientCalls.Inc()

	// Parse the PostgreSQL wire protocol message using the SDK.
	req, err := postgres.HandleClientMessage(req, p.Logger)
	if err != nil {
		p.Logger.Debug("Failed to handle client message", "error", err)
	}

	// Delegate to the auth handler state machine.
	return p.AuthHandler.HandleTrafficFromClient(ctx, req)
}

// OnClosed cleans up the session when a client connection closes.
func (p *Plugin) OnClosed(_ context.Context, req *v1.Struct) (*v1.Struct, error) {
	clientRemote := getClientRemote(req)
	if clientRemote != "" {
		p.AuthHandler.Sessions.Remove(clientRemote)
	}
	return req, nil
}

// OnTrafficFromServer is a pass-through -- no modifications needed.
func (p *Plugin) OnTrafficFromServer(
	_ context.Context, req *v1.Struct,
) (*v1.Struct, error) {
	return req, nil
}

// sendTerminateResponse sets the response bytes and terminate signal on the request.
func sendTerminateResponse(req *v1.Struct, response []byte, logger hclog.Logger) (*v1.Struct, error) {
	signals := []any{
		sdkAct.Terminate().ToMap(),
		sdkAct.Log("debug", "Auth plugin response", map[string]any{
			"plugin": PluginID.GetName(),
		}).ToMap(),
	}

	signalsList, err := v1.NewList(signals)
	if err != nil {
		logger.Error("Failed to create signals list", "error", err)
		// Fall back to just setting the response without signals.
		req.Fields[FieldResponse] = v1.NewBytesValue(response)
		return req, nil
	}

	req.Fields[sdkAct.Signals] = v1.NewListValue(signalsList)
	req.Fields[FieldResponse] = v1.NewBytesValue(response)
	return req, nil
}
