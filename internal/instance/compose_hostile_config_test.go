package instance

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
	"gopkg.in/yaml.v3"
)

// TestHostileConfigIdentifiersCannotAddComposeServices: the instance name, the
// database type and the honeypot names are written into docker-compose.yml
// as they are (a comment, container names, service keys, bind-mount paths),
// and config.Parse took any string for them. A config file with a newline in
// one of them added a whole service of its choosing - privileged, host PID and
// network, the host's / mounted - to a file that still parsed, and `qpot up`
// started it. Such a file is now refused when it is read.
func TestHostileConfigIdentifiersCannotAddComposeServices(t *testing.T) {
	const pwn = `"%s\n  pwn:\n    image: alpine\n    privileged: true\n    pid: host\n    network_mode: host\n    volumes:\n      - /:/host\n#"`
	inject := func(s string) string { return strings.Replace(pwn, "%s", s, 1) }
	cases := map[string]string{
		"database type": "database:\n  type: " + inject("none") + "\n",
		"instance name": "instance_name: " + inject("edge") + "\n",
		"honeypot name": "honeypots:\n  " + inject("cowrie") + ":\n    enabled: true\n    port: 22\n",
		"data path":     "data_path: " + inject("/var/lib/qpot") + "\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "edge", "config.yaml")
			cfg, err := config.Parse([]byte(doc), path)
			if err != nil {
				return // refused: nothing reaches the compose file
			}
			cfg.QPotID = "qp_" + strings.Repeat("a", 24)
			sb, err := security.NewSandbox(&cfg.Security)
			if err != nil {
				t.Fatalf("NewSandbox: %v", err)
			}
			out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
			if err != nil {
				return // not rendered either
			}
			var doc struct {
				Services map[string]struct {
					Privileged bool     `yaml:"privileged"`
					PID        string   `yaml:"pid"`
					Volumes    []string `yaml:"volumes"`
				} `yaml:"services"`
			}
			if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
				return // a broken file is not started
			}
			if svc, ok := doc.Services["pwn"]; ok {
				t.Fatalf("the config value added a service to the compose file: %+v", svc)
			}
		})
	}
}
