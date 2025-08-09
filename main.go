package main

import (
	"crypto/rand"
	"flag"
	"os"

	"github.com/gatewayd-io/gatewayd-plugin-auth/plugin"
	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/logging"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/metrics"
	p "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	apiV1 "github.com/gatewayd-io/gatewayd/api/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/spf13/cast"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Parse command line flags, passed by GatewayD via the plugin config
	logLevel := flag.String("log-level", "info", "Log level")
	flag.Parse()

	logger := hclog.New(&hclog.LoggerOptions{
		Level:      logging.GetLogLevel(*logLevel),
		Output:     os.Stderr,
		JSONFormat: true,
		Color:      hclog.ColorOff,
	})

	// Generate a random 4 bytes salt
	// TODO: Make this dynamically rotatable or generate a new one per client connection
	var salt [plugin.SALT_SIZE]byte
	if _, err := rand.Read(salt[:]); err != nil {
		// If we can't generate a salt, we can't authenticate
		// If you reach this point, you should probably start
		// looking for a new job! Farming is a good option.
		logger.Error("Failed to generate salt", "error", err)
		os.Exit(1)
	}

	pluginInstance := plugin.NewTemplatePlugin(plugin.Plugin{
		Logger:        logger,
		ClientInfo:    make(map[plugin.ConnPair]plugin.Session),
		AuthType:      plugin.MD5,
		Salt:          salt,
		ScramSessions: make(map[plugin.ConnPair]*plugin.ScramSHA256),
	})

	if cfg := cast.ToStringMap(plugin.PluginConfig["config"]); cfg != nil {
		metricsConfig := metrics.NewMetricsConfig(cfg)
		if metricsConfig != nil && metricsConfig.Enabled {
			go metrics.ExposeMetrics(metricsConfig, logger)
		}

		pluginInstance.Impl.APIAddress = cast.ToString(cfg["apiGRPCAddress"])
		apiClient, err := grpc.NewClient(
			pluginInstance.Impl.APIAddress,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil || apiClient == nil {
			logger.Error("Failed to initialize API client", "error", err)
			os.Exit(1)
		}
		defer apiClient.Close()
		pluginInstance.Impl.APIClient = apiV1.NewGatewayDAdminAPIServiceClient(apiClient)

		pluginInstance.Impl.AuthType = plugin.AuthType(cast.ToString(cfg["authType"]))

		// Initialize credential store
		credentialBackend := plugin.CredentialBackend(cast.ToString(cfg["credentialBackend"]))
		credentialConfig := cast.ToStringMap(cfg["credentialConfig"])
		if credentialConfig == nil {
			credentialConfig = make(map[string]interface{})
		}

		credentialStore, err := plugin.NewCredentialStore(credentialBackend, credentialConfig, logger)
		if err != nil {
			logger.Error("Failed to initialize credential store", "error", err, "backend", credentialBackend)
			os.Exit(1)
		}
		pluginInstance.Impl.CredentialStore = credentialStore

		// Initialize certificate authenticator if enabled
		certAuthConfig := cast.ToStringMap(cfg["certificateAuth"])
		if certAuthConfig != nil && cast.ToBool(certAuthConfig["enabled"]) {
			caPool, err := plugin.LoadCAPool(certAuthConfig)
			if err != nil {
				logger.Error("Failed to load CA pool", "error", err)
				os.Exit(1)
			}

			requireValidCA := cast.ToBool(certAuthConfig["require_valid_ca"])
			pluginInstance.Impl.CertAuth = plugin.NewCertificateAuthenticator(
				logger,
				credentialStore,
				caPool,
				requireValidCA,
			)
		}
	}

	plugin.NewFSM(logger)

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
