package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// MandatoryControl is one container hardening measure every attacker-facing
// service gets. It has no off switch: the compose template renders it whatever
// the config says, and a config file that asks for it to be off is corrected
// when loaded (see enforceMandatoryContainment).
type MandatoryControl struct {
	// Key is the security.* setting that used to switch the control.
	Key string
	// Summary says what the control does, for doctor output and the docs.
	Summary string
}

// MandatoryControls lists the hardening that cannot be turned off. Keep
// doc/security.md ("Mandatory containment controls") in step with it.
var MandatoryControls = []MandatoryControl{
	{"read_only_filesystem", "read-only root filesystem, with tmpfs scratch space"},
	{"drop_capabilities", "all Linux capabilities dropped, with a minimal add-back per image"},
	{"no_new_privileges", "no-new-privileges, so setuid binaries cannot raise privileges"},
	{"network_isolation.separate_networks", "one bridge network per honeypot, never the host network"},
}

// enforceMandatoryContainment switches every mandatory control on and returns
// one message per control the file explicitly asked to turn off. A file that
// merely omits them (hand-written, or trimmed to the settings that matter)
// reads as false in YAML; before this such a file ran honeypots with Docker's
// default capabilities and a writable root, and said nothing.
func (c *Config) enforceMandatoryContainment(data []byte) []string {
	var explicit struct {
		Security struct {
			ReadOnlyFilesystem *bool `yaml:"read_only_filesystem"`
			DropCapabilities   *bool `yaml:"drop_capabilities"`
			NoNewPrivileges    *bool `yaml:"no_new_privileges"`
			NetworkIsolation   struct {
				SeparateNetworks *bool `yaml:"separate_networks"`
			} `yaml:"network_isolation"`
		} `yaml:"security"`
	}
	// The file parsed once already; a failure here only loses the messages.
	_ = yaml.Unmarshal(data, &explicit)
	var ignored []string
	for i, set := range []*bool{
		explicit.Security.ReadOnlyFilesystem,
		explicit.Security.DropCapabilities,
		explicit.Security.NoNewPrivileges,
		explicit.Security.NetworkIsolation.SeparateNetworks,
	} {
		if set != nil && !*set {
			ignored = append(ignored, fmt.Sprintf("security.%s: false is ignored; this containment control is mandatory (%s)",
				MandatoryControls[i].Key, MandatoryControls[i].Summary))
		}
	}
	c.Security.ReadOnlyFilesystem = true
	c.Security.DropCapabilities = true
	c.Security.NoNewPrivileges = true
	c.Security.NetworkIsolation.SeparateNetworks = true
	return ignored
}

// sensorIDEncoding matches the QPot ID's alphabet, so a sensor ID has the
// same length and shape as the credential it replaces in stored telemetry.
var sensorIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// SensorIDFor derives the telemetry identifier of the instance whose QPot ID
// is qpotID: "qs_" and 24 characters, the QPot ID's own length. It names the
// instance in events, collector output and log backups. It is not a
// credential: it is a keyed one-way function of the QPot ID, so reading it
// (from a backup, a collector log, a SIEM) does not give API access.
func SensorIDFor(qpotID string) string {
	if qpotID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(qpotID))
	_, _ = mac.Write([]byte("qpot sensor id v1"))
	return "qs_" + strings.ToLower(sensorIDEncoding.EncodeToString(mac.Sum(nil)))[:24]
}

// SensorID is this instance's telemetry identifier (see SensorIDFor).
func (c *Config) SensorID() string { return SensorIDFor(c.QPotID) }

// AuthMode names how the web UI and API authenticate: "qpot-id", "basic", or
// "none". Basic needs both a username and a password; with either one empty
// every request is let through, which is "none".
func (w WebUIConfig) AuthMode() string {
	switch {
	case w.QPotIDAuth:
		return "qpot-id"
	case w.Username != "" && w.Password != "":
		return "basic"
	}
	return "none"
}

// LoopbackOnly reports whether the web UI listens only on this computer. An
// empty address, a name other than localhost, an unspecified address
// (0.0.0.0, ::) and anything unparseable all count as reachable from outside.
func (w WebUIConfig) LoopbackOnly() bool {
	host := strings.TrimSpace(w.BindAddr)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ExposureError is returned for a web UI that would serve the management API
// to other computers without any login.
type ExposureError struct{ BindAddr string }

func (e *ExposureError) Error() string {
	return fmt.Sprintf("the web UI and API have no login (web_ui.qpot_id_auth is false and no web_ui username and password are set) and web_ui.bind_addr %q is reachable from other computers", e.BindAddr)
}

// CheckExposure refuses the one combination that hands the management API to
// anyone who can reach the port: no authentication on an address other than
// loopback. With a login, or on loopback, it returns nil.
func (w WebUIConfig) CheckExposure() error {
	if w.AuthMode() != "none" || w.LoopbackOnly() {
		return nil
	}
	return &ExposureError{BindAddr: w.BindAddr}
}
