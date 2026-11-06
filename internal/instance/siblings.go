package instance

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// siblingReservations returns the host ports and subnets already used by the
// OTHER QPot instances next to dataPath (~/.qpot/instances/<name>), read from
// their rendered docker-compose.yml - the ground truth of what each one
// publishes. Allocation is otherwise per-instance only, so two instances could
// be handed the same host port or /24 and the second `qpot up` failed with
// "port is already allocated" / "Pool overlaps". A missing or unparsable file
// reserves nothing.
func siblingReservations(dataPath string) (map[int]bool, map[string]bool) {
	ports, subnets := map[int]bool{}, map[string]bool{}
	if dataPath == "" {
		return ports, subnets
	}
	self := filepath.Clean(dataPath)
	root := filepath.Dir(self)
	entries, err := os.ReadDir(root)
	if err != nil {
		return ports, subnets
	}
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if !e.IsDir() || dir == self {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
		if err != nil {
			continue
		}
		collectComposeReservations(data, ports, subnets)
	}
	return ports, subnets
}

// collectComposeReservations adds the published host ports and ipam subnets of
// one compose file to ports/subnets.
func collectComposeReservations(data []byte, ports map[int]bool, subnets map[string]bool) {
	var doc struct {
		Services map[string]struct {
			Ports []string `yaml:"ports"`
		} `yaml:"services"`
		Networks map[string]struct {
			IPAM struct {
				Config []struct {
					Subnet string `yaml:"subnet"`
				} `yaml:"config"`
			} `yaml:"ipam"`
		} `yaml:"networks"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return
	}
	for _, svc := range doc.Services {
		for _, p := range svc.Ports {
			if hp := publishedHostPort(p); hp > 0 {
				ports[hp] = true
			}
		}
	}
	for _, n := range doc.Networks {
		for _, c := range n.IPAM.Config {
			if c.Subnet != "" {
				subnets[c.Subnet] = true
			}
		}
	}
}

// ownHostPorts returns the host port each (service, container port) pair has
// in the instance's own compose file, by portKey: the ports its running
// services hold. A missing or unparsable file gives none.
func ownHostPorts(composePath string) map[string]int {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil
	}
	var doc struct {
		Services map[string]struct {
			Ports []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	out := map[string]int{}
	for name, svc := range doc.Services {
		for _, spec := range svc.Ports {
			host := publishedHostPort(spec)
			bare, _, _ := strings.Cut(spec, "/")
			parts := strings.Split(bare, ":")
			container, err := strconv.Atoi(parts[len(parts)-1])
			if host > 0 && err == nil {
				out[portKey(name, container)] = host
			}
		}
	}
	return out
}

// publishedHostPort extracts the host port from a compose short-syntax port
// ("8080:80", "127.0.0.1:19000:9000", "53:53/udp"); 0 if there is none.
func publishedHostPort(spec string) int {
	spec, _, _ = strings.Cut(spec, "/")
	parts := strings.Split(spec, ":")
	if len(parts) < 2 {
		return 0 // container port only: nothing published on a fixed host port
	}
	n, err := strconv.Atoi(parts[len(parts)-2])
	if err != nil {
		return 0
	}
	return n
}

// hostDockerSubnets returns the subnets of the docker networks on this host
// that do not belong to the given compose project (whose own networks are
// re-rendered with the same subnets). Errors (no docker) yield nothing.
func hostDockerSubnets(ctx context.Context, project string) []*net.IPNet {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ids, err := exec.CommandContext(ctx, "docker", "network", "ls", "-q").Output()
	if err != nil || len(strings.Fields(string(ids))) == 0 {
		return nil
	}
	out, err := exec.CommandContext(ctx, "docker", append([]string{"network", "inspect"}, strings.Fields(string(ids))...)...).Output()
	if err != nil {
		return nil
	}
	return parseNetworkInspect(out, project)
}

// parseNetworkInspect extracts the IPv4/IPv6 subnets from `docker network
// inspect` JSON, skipping networks of the given compose project.
func parseNetworkInspect(data []byte, project string) []*net.IPNet {
	var nets []struct {
		Labels map[string]string `json:"Labels"`
		IPAM   struct {
			Config []struct {
				Subnet string `json:"Subnet"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if json.Unmarshal(data, &nets) != nil {
		return nil
	}
	var out []*net.IPNet
	for _, n := range nets {
		if project != "" && n.Labels["com.docker.compose.project"] == project {
			continue
		}
		for _, c := range n.IPAM.Config {
			if _, ipn, err := net.ParseCIDR(c.Subnet); err == nil {
				out = append(out, ipn)
			}
		}
	}
	return out
}
