package plugin

import (
	"context"
	"encoding/json"

	"google.golang.org/protobuf/types/known/emptypb"
)

type Server struct {
	Network              string         `json:"network"`
	Address              string         `json:"address"`
	Status               uint           `json:"status"`
	TickInterval         int64          `json:"tickInterval"`
	LoadbalancerStrategy map[string]any `json:"loadBalancer"`
	IsTLSEnabled         bool           `json:"isTLSEnabled"`
}

// getServers returns a list of servers from GatewayD.
func (p *Plugin) getServers() map[string]Server {
	if p.APIClient == nil {
		p.Logger.Error(
			"Failed to get a list of servers from GatewayD",
			"error", "API client is not initialized",
		)
		return nil
	}

	servers, err := p.APIClient.GetServers(context.Background(), &emptypb.Empty{})
	if err != nil {
		p.Logger.Error("Failed to get a list of servers from GatewayD", "error", err)
		return nil
	}

	data, err := servers.MarshalJSON()
	if err != nil {
		p.Logger.Error("Failed to marshal response from GatewayD", "error", err)
		return nil
	}

	var serverMap map[string]Server
	if err = json.Unmarshal(data, &serverMap); err != nil {
		p.Logger.Error("Failed to unmarshal response from GatewayD", "error", err)
		return nil
	}

	return serverMap
}

// filterServers filters servers by network and address.
func (p *Plugin) filterServers(network, address string) map[string]Server {
	servers := p.getServers()
	if servers == nil {
		return nil
	}

	filteredServers := make(map[string]Server)
	for name, server := range servers {
		if server.Network == network && server.Address == address {
			filteredServers[name] = server
		}
	}

	return filteredServers
}
