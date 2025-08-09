package plugin

import (
	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
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
			"authType":                sdkConfig.GetEnv("AUTH_TYPE", "scram-sha-256"),
			"apiGRPCAddress":          sdkConfig.GetEnv("API_GRPC_ADDRESS", "localhost:19090"),
			"credentialBackend":       sdkConfig.GetEnv("CREDENTIAL_BACKEND", "env"),
			"credentialConfig": map[string]interface{}{
				"file_path":                  sdkConfig.GetEnv("CREDENTIAL_FILE_PATH", "/etc/gatewayd/credentials.json"),
				"vault_address":              sdkConfig.GetEnv("VAULT_ADDRESS", ""),
				"vault_token":                sdkConfig.GetEnv("VAULT_TOKEN", ""),
				"vault_mount_path":           sdkConfig.GetEnv("VAULT_MOUNT_PATH", "secret"),
				"vault_insecure_skip_verify": sdkConfig.GetEnv("VAULT_INSECURE_SKIP_VERIFY", "false"),
			},
			"certificateAuth": map[string]interface{}{
				"enabled":                sdkConfig.GetEnv("CERT_AUTH_ENABLED", "false"),
				"require_valid_ca":       sdkConfig.GetEnv("CERT_REQUIRE_VALID_CA", "true"),
				"use_system_ca":          sdkConfig.GetEnv("CERT_USE_SYSTEM_CA", "false"),
				"ca_data":                sdkConfig.GetEnv("CERT_CA_DATA", ""),
				"username_mapping_rules": sdkConfig.GetEnv("CERT_USERNAME_MAPPING_RULES", ""),
			},
            "authorization": map[string]interface{}{
                "enabled":       sdkConfig.GetEnv("AUTHZ_ENABLED", "false"),
                "model_path":    sdkConfig.GetEnv("AUTHZ_MODEL_PATH", ""),
                "policy_path":   sdkConfig.GetEnv("AUTHZ_POLICY_PATH", ""),
                "watch":         sdkConfig.GetEnv("AUTHZ_WATCH", "false"),
            },
		},
		"hooks": []interface{}{
			int32(v1.HookName_HOOK_NAME_ON_TRAFFIC_FROM_CLIENT),
			int32(v1.HookName_HOOK_NAME_ON_TRAFFIC_FROM_SERVER),
		},
		"tags":       []interface{}{"plugin", "auth"},
		"categories": []interface{}{"auth"},
	}
)
