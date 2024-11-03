package plugin

import (
	"context"
	"encoding/json"
	"strings"

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

// filterServers filters servers by address.
func (p *Plugin) filterServers(address string) map[string]Server {
	servers := p.getServers()
	if servers == nil {
		return nil
	}

	hostPort := strings.Split(address, ":")
	if len(hostPort) != 2 {
		p.Logger.Error(
			"Failed to split host and port",
			"address", address,
		)
		return nil
	}

	filteredServers := make(map[string]Server)
	for name, server := range servers {
		serverHostPort := strings.Split(server.Address, ":")
		if len(serverHostPort) != 2 {
			p.Logger.Error(
				"Failed to split host and port",
				"address", server.Address,
			)
			continue
		}

		// TODO: Figure out a way to compare the hosts.
		// The server may listen on 0.0.0.0, and the incoming address may be a specific IP,
		// like 127.0.0.1.
		if hostPort[1] == serverHostPort[1] {
			filteredServers[name] = server
			break
		}
	}

	return filteredServers
}
