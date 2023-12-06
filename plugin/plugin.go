package plugin

import (
	"context"

	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
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
	// Example req:
	// {
	//     "client": {
	//         "local": "0.0.0.0:15432",
	//         "remote": "127.0.0.1:45612"
	//     },
	//     "error": "",
	//     "query": "eyJUeXBlIjoiUXVlcnkiLCJTdHJpbmciOiJzZWxlY3QgMTsifQ==",
	//     "request": "UQAAAA5zZWxlY3QgMTsA",
	//     "server": {
	//         "local": "127.0.0.1:60386",
	//         "remote": "127.0.0.1:5432"
	//     }
	// }
	p.Logger.Debug("OnTrafficFromClient", "req", req)

	request := req.Fields["request"].GetBytesValue()
	p.Logger.Debug("OnTrafficFromClient", "request", string(request))

	return req, nil
}
