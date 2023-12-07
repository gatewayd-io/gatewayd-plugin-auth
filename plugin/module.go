package plugin

import (
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
)

var (
	PluginID = v1.PluginID{
		Name:      "gatewayd-plugin-auth",
		Version:   "0.0.1",
		RemoteUrl: "github.com/gatewayd-io/gatewayd-plugin-auth",
	}
	PluginMap = map[string]goplugin.Plugin{
		"gatewayd-plugin-auth": &AuthPlugin{},
	}
	// TODO: Handle this in a better way
	// https://github.com/gatewayd-io/gatewayd-plugin-sdk/issues/3
	PluginConfig = map[string]interface{}{
		"id": map[string]interface{}{
			"name":      PluginID.GetName(),
			"version":   PluginID.GetVersion(),
			"remoteUrl": PluginID.GetRemoteUrl(),
		},
		"description": "GatewayD plugin for authentication",
		"authors": []interface{}{
			"Mostafa Moradian <mostafa@gatewayd.io>",
		},
		"license":    "Apache 2.0",
		"projectUrl": "https://github.com/gatewayd-io/gatewayd-plugin-auth",
		// Compile-time configuration
		"config": map[string]interface{}{
			"metricsEnabled":          "true",
			"metricsUnixDomainSocket": "/tmp/gatewayd-plugin-auth.sock",
			"metricsEndpoint":         "/metrics",
		},
		"hooks": []interface{}{
			int32(v1.HookName_HOOK_NAME_ON_TRAFFIC_FROM_CLIENT),
			int32(v1.HookName_HOOK_NAME_ON_TRAFFIC_FROM_SERVER),
		},
		"tags":       []interface{}{"plugin", "auth"},
		"categories": []interface{}{"auth"},
	}
)
