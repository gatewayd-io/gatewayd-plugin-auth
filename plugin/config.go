package plugin

import (
	"fmt"

	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
)

// DefaultSessionTTLSeconds is the default TTL for auth sessions in seconds.
const DefaultSessionTTLSeconds = 3600

// ConfigValues holds the runtime configuration for the auth plugin.
type ConfigValues struct {
	// AuthType is the default authentication method.
	AuthType AuthType
	// CredentialsFile is the path to the YAML credentials file.
	CredentialsFile string
	// ServerVersion is the PostgreSQL server version to advertise to clients.
	ServerVersion string
	// SessionTTLSeconds is the TTL for auth sessions in seconds.
	SessionTTLSeconds int
	// MetricsEnabled controls Prometheus metrics exposure.
	MetricsEnabled bool
	// MetricsUnixDomainSocket is the Unix socket path for metrics.
	MetricsUnixDomainSocket string
	// MetricsEndpoint is the HTTP endpoint for metrics.
	MetricsEndpoint string
	// CasbinModelPath is the path to the Casbin model file (optional).
	CasbinModelPath string
	// CasbinPolicyPath is the path to the Casbin policy file (optional).
	CasbinPolicyPath string
	// AuthorizationEnabled controls whether query authorization is active.
	AuthorizationEnabled bool
}

// DefaultConfig returns the default plugin configuration.
func DefaultConfig() *ConfigValues {
	return &ConfigValues{
		AuthType:                AuthMD5,
		CredentialsFile:         sdkConfig.GetEnv("CREDENTIALS_FILE", "credentials.yaml"),
		ServerVersion:           sdkConfig.GetEnv("SERVER_VERSION", "17.4"),
		SessionTTLSeconds:       DefaultSessionTTLSeconds,
		MetricsEnabled:          true,
		MetricsUnixDomainSocket: "/tmp/gatewayd-plugin-auth.sock",
		MetricsEndpoint:         "/metrics",
		CasbinModelPath:         sdkConfig.GetEnv("CASBIN_MODEL_PATH", ""),
		CasbinPolicyPath:        sdkConfig.GetEnv("CASBIN_POLICY_PATH", ""),
		AuthorizationEnabled:    false,
	}
}

// ParseConfig parses runtime config from the plugin's config map.
func ParseConfig(cfg map[string]interface{}) *ConfigValues {
	config := DefaultConfig()

	if v, ok := cfg["authType"]; ok {
		config.AuthType = AuthType(fmt.Sprint(v))
	}
	if v, ok := cfg["credentialsFile"]; ok {
		config.CredentialsFile = fmt.Sprint(v)
	}
	if v, ok := cfg["serverVersion"]; ok {
		config.ServerVersion = fmt.Sprint(v)
	}
	if v, ok := cfg["sessionTTLSeconds"]; ok {
		if ttl, ok := v.(float64); ok {
			config.SessionTTLSeconds = int(ttl)
		}
	}
	if v, ok := cfg["metricsEnabled"]; ok {
		config.MetricsEnabled = fmt.Sprint(v) == "true"
	}
	if v, ok := cfg["metricsUnixDomainSocket"]; ok {
		config.MetricsUnixDomainSocket = fmt.Sprint(v)
	}
	if v, ok := cfg["metricsEndpoint"]; ok {
		config.MetricsEndpoint = fmt.Sprint(v)
	}
	if v, ok := cfg["casbinModelPath"]; ok {
		config.CasbinModelPath = fmt.Sprint(v)
	}
	if v, ok := cfg["casbinPolicyPath"]; ok {
		config.CasbinPolicyPath = fmt.Sprint(v)
	}
	if v, ok := cfg["authorizationEnabled"]; ok {
		config.AuthorizationEnabled = fmt.Sprint(v) == "true"
	}

	return config
}
