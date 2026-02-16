package plugin

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AuthSuccesses counts successful authentications.
	AuthSuccesses = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gatewayd",
		Name:      "auth_successes_total",
		Help:      "Total number of successful authentications",
	})

	// AuthFailures counts failed authentication attempts.
	AuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gatewayd",
		Name:      "auth_failures_total",
		Help:      "Total number of failed authentication attempts",
	})

	// AuthzDenials counts authorization denials.
	AuthzDenials = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gatewayd",
		Name:      "authz_denials_total",
		Help:      "Total number of authorization denials",
	})

	// OnTrafficFromClientCalls counts OnTrafficFromClient hook invocations.
	OnTrafficFromClientCalls = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gatewayd",
		Name:      "auth_on_traffic_from_client_total",
		Help:      "Total number of OnTrafficFromClient hook calls",
	})

	// GetPluginConfigCalls counts GetPluginConfig invocations.
	GetPluginConfigCalls = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gatewayd",
		Name:      "auth_get_plugin_config_total",
		Help:      "Total number of GetPluginConfig calls",
	})

	// ActiveSessions tracks the current number of active auth sessions.
	ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "gatewayd",
		Name:      "auth_active_sessions",
		Help:      "Current number of active authentication sessions",
	})
)
