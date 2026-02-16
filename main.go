package main

import (
	"flag"
	"os"
	"time"

	"github.com/gatewayd-io/gatewayd-plugin-auth/plugin"
	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/logging"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/metrics"
	p "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/spf13/cast"
)

func main() {
	logLevel := flag.String("log-level", "info", "Log level")
	flag.Parse()

	logger := hclog.New(&hclog.LoggerOptions{
		Level:      logging.GetLogLevel(*logLevel),
		Output:     os.Stderr,
		JSONFormat: true,
		Color:      hclog.ColorOff,
	})

	// Parse config from the plugin's compile-time config.
	cfg := cast.ToStringMap(plugin.PluginConfig["config"])
	pluginCfg := plugin.DefaultConfig()
	if cfg != nil {
		pluginCfg = plugin.ParseConfig(cfg)
	}

	// Start metrics if enabled.
	if cfg != nil && pluginCfg.MetricsEnabled {
		metricsConfig := metrics.NewMetricsConfig(cfg)
		if metricsConfig != nil && metricsConfig.Enabled {
			go metrics.ExposeMetrics(metricsConfig, logger)
		}
	}

	// Load credential store.
	credStore, err := plugin.NewFileCredentialStore(pluginCfg.CredentialsFile)
	if err != nil {
		logger.Error("Failed to load credentials", "error", err, "file", pluginCfg.CredentialsFile)
		os.Exit(1)
	}
	logger.Info("Loaded credentials", "file", pluginCfg.CredentialsFile)

	// Initialize authorizer (optional).
	authorizer, err := plugin.NewAuthorizer(
		pluginCfg.CasbinModelPath,
		pluginCfg.CasbinPolicyPath,
		logger,
	)
	if err != nil {
		logger.Error("Failed to initialize authorizer", "error", err)
		os.Exit(1)
	}
	if authorizer != nil {
		logger.Info("Authorization enabled",
			"model", pluginCfg.CasbinModelPath,
			"policy", pluginCfg.CasbinPolicyPath)
	}

	// Create session manager with TTL-based cleanup.
	sessionTTL := time.Duration(pluginCfg.SessionTTLSeconds) * time.Second
	sessions := plugin.NewSessionManager(sessionTTL)
	done := make(chan struct{})
	defer close(done)
	sessions.StartCleanupLoop(time.Minute, done)

	// Create auth handler.
	authHandler := plugin.NewAuthHandler(
		logger,
		sessions,
		credStore,
		authorizer,
		pluginCfg.AuthType,
		pluginCfg.ServerVersion,
	)

	// Create plugin instance.
	pluginInstance := &plugin.AuthGRPCPlugin{
		Impl: plugin.Plugin{
			Logger:      logger,
			AuthHandler: authHandler,
		},
	}

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   sdkConfig.GetEnv("MAGIC_COOKIE_KEY", ""),
			MagicCookieValue: sdkConfig.GetEnv("MAGIC_COOKIE_VALUE", ""),
		},
		Plugins: v1.GetPluginSetMap(map[string]goplugin.Plugin{
			plugin.PluginID.GetName(): pluginInstance,
		}),
		GRPCServer: p.DefaultGRPCServer,
		Logger:     logger,
	})
}
