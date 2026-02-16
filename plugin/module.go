package plugin

import (
	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
)

var (
	// PluginID identifies this plugin.
	PluginID = v1.PluginID{
		Name:      "gatewayd-plugin-auth",
		Version:   "1.0.0",
		RemoteUrl: "github.com/gatewayd-io/gatewayd-plugin-auth",
	}

	// PluginMap is the plugin map for HashiCorp go-plugin.
	PluginMap = map[string]goplugin.Plugin{
		"gatewayd-plugin-auth": &AuthGRPCPlugin{},
	}

	// PluginConfig is the compile-time plugin configuration returned to GatewayD.
	PluginConfig = map[string]interface{}{
		"id": map[string]interface{}{
			"name":      PluginID.GetName(),
			"version":   PluginID.GetVersion(),
			"remoteUrl": PluginID.GetRemoteUrl(),
		},
		"description": "GatewayD plugin for authentication, authorization, and access control",
		"authors": []interface{}{
			"Mostafa Moradian <mostafa@gatewayd.io>",
		},
		"license":    "Apache 2.0",
		"projectUrl": "https://github.com/gatewayd-io/gatewayd-plugin-auth",
		"config": map[string]interface{}{
			"metricsEnabled":          "true",
			"metricsUnixDomainSocket": "/tmp/gatewayd-plugin-auth.sock",
			"metricsEndpoint":         "/metrics",
			"authType":                sdkConfig.GetEnv("AUTH_TYPE", "md5"),
			"credentialsFile":         sdkConfig.GetEnv("CREDENTIALS_FILE", "credentials.yaml"),
			"serverVersion":           sdkConfig.GetEnv("SERVER_VERSION", "17.4"),
			"authorizationEnabled":    sdkConfig.GetEnv("AUTHORIZATION_ENABLED", "false"),
			"casbinModelPath":         sdkConfig.GetEnv("CASBIN_MODEL_PATH", ""),
			"casbinPolicyPath":        sdkConfig.GetEnv("CASBIN_POLICY_PATH", ""),
		},
		"hooks": []interface{}{
			int32(v1.HookName_HOOK_NAME_ON_TRAFFIC_FROM_CLIENT),
			int32(v1.HookName_HOOK_NAME_ON_CLOSED),
		},
		"tags":       []interface{}{"plugin", "auth", "authorization", "access-control"},
		"categories": []interface{}{"auth", "security"},
	}
)
