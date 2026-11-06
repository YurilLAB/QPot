package instance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
)

type heraldingCapability struct {
	Enabled bool           `yaml:"enabled"`
	Port    int            `yaml:"port"`
	Data    map[string]any `yaml:"protocol_specific_data"`
}

func heraldingCapabilities(t *testing.T) map[string]heraldingCapability {
	t.Helper()
	var doc struct {
		Capabilities map[string]heraldingCapability `yaml:"capabilities"`
	}
	if err := yaml.Unmarshal(heraldingConfig, &doc); err != nil {
		t.Fatalf("heralding.yml does not parse: %v", err)
	}
	return doc.Capabilities
}

// heraldingUnset mirrors heralding's certs.is_unset: values it replaces with
// the persona's.
func heraldingUnset(v any) bool {
	switch s := v.(type) {
	case nil:
		return true
	case string:
		return s == "" || s == "None" || s == "none" || s == "null"
	}
	return false
}

// TestHeraldingConfigLeavesIdentityToPersona guards the config QPot mounts over
// the image's: no capability may override what heralding's persona says about
// the machine. The image's own file set stock greetings (OpenSSH 6.6.1p1 on
// Ubuntu 14.04, "Microsoft FTP Server", Exchange SMTP) that every install
// shared and that contradicted the persona on the other ports.
func TestHeraldingConfigLeavesIdentityToPersona(t *testing.T) {
	caps := heraldingCapabilities(t)
	if len(caps) < 20 {
		t.Fatalf("heralding.yml has %d capabilities, want the image's full list", len(caps))
	}
	for name, c := range caps {
		for _, key := range []string{"banner", "syst_type", "version", "fqdn"} {
			if v, ok := c.Data[key]; ok && !heraldingUnset(v) {
				t.Errorf("%s.%s = %v overrides the persona", name, key, v)
			}
		}
		cert, _ := c.Data["cert"].(map[string]any)
		for _, key := range []string{"country", "state", "locality", "organization", "organizational_unit"} {
			if v, ok := cert[key]; ok && !heraldingUnset(v) {
				t.Errorf("%s.cert.%s = %v overrides the persona", name, key, v)
			}
		}
		if cn, ok := cert["common_name"]; ok && cn != "*" && !heraldingUnset(cn) {
			t.Errorf("%s.cert.common_name = %v overrides the persona's host name", name, cn)
		}
		if v, ok := cert["serial_number"]; ok && v != 0 {
			t.Errorf("%s.cert.serial_number = %v: every install would share it", name, v)
		}
	}
	var body []string
	for _, ln := range strings.Split(string(heraldingConfig), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(ln), "#") {
			body = append(body, ln)
		}
	}
	for _, stock := range []string{"OpenSSH_6.6", "Microsoft", "Windows-NT", "Server Ready", "server ready", "\"US\"", " US\n"} {
		if strings.Contains(strings.Join(body, "\n")+"\n", stock) {
			t.Errorf("heralding.yml still sets %q", stock)
		}
	}
}

// TestHeraldingPublishesOnlyListeningPorts: every port QPot publishes for
// heralding must be an enabled capability of the config it runs, or the port
// accepts connections and drops them.
func TestHeraldingPublishesOnlyListeningPorts(t *testing.T) {
	listening := map[int]bool{}
	for _, c := range heraldingCapabilities(t) {
		if c.Enabled {
			listening[c.Port] = true
		}
	}
	for _, p := range deployProfile(config.Default("heralding-ports"), "heralding").Ports {
		if !listening[p] {
			t.Errorf("port %d is published but no heralding capability listens on it", p)
		}
	}
}

// TestHeraldingKeepsItsMachine: heralding keeps the persona it drew, its TLS
// certificates and its SSH host keys in its working directory, /tmp/heralding.
// On a tmpfs it became a different machine (new name, OS, certificates, host
// keys) on every restart, so the directory must be a persistent volume, and
// the config must be QPot's, mounted read-only.
func TestHeraldingKeepsItsMachine(t *testing.T) {
	d := deployProfile(config.Default("heralding-state"), "heralding")
	for _, tm := range d.Tmpfs {
		if strings.HasPrefix(tm, "/tmp/heralding") {
			t.Errorf("heralding working dir is a tmpfs: %q", tm)
		}
	}
	var state, conf bool
	for _, v := range d.Volumes {
		switch v.ContainerPath {
		case "/tmp/heralding":
			state = v.HostSubdir == "state" && !v.File && !v.ReadOnly
		case "/etc/heralding/heralding.yml":
			conf = v.File && v.ReadOnly && string(v.Content) == string(heraldingConfig)
		}
	}
	if !state || !conf {
		t.Fatalf("heralding volumes: state=%v config=%v: %+v", state, conf, d.Volumes)
	}

	cfg := config.Default("heralding-compose")
	hp := cfg.Honeypots["heralding"]
	hp.Enabled = true
	cfg.Honeypots["heralding"] = hp
	svc, tcp, _ := publishedPorts(t, cfg, "heralding")
	if len(tcp) != len(d.Ports) {
		t.Errorf("compose publishes %v, profile %v", tcp, d.Ports)
	}
	for _, want := range []string{
		"/honeypots/heralding/state:/tmp/heralding\n",
		"/honeypots/heralding/heralding.yml:/etc/heralding/heralding.yml:ro\n",
	} {
		if !strings.Contains(svc, want) {
			t.Errorf("heralding service lacks %q", strings.TrimSpace(want))
		}
	}
	if strings.Contains(svc, "/tmp/heralding:uid=") {
		t.Error("heralding service still mounts a tmpfs working dir")
	}
}
