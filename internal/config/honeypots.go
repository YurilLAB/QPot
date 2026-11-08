package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// SetHoneypotCustomConfig replaces one configured honeypot's custom_config
// under the honeypot lock, so it is safe while the web server reads the
// config. It reports false (and changes nothing) for a honeypot the config
// does not have.
func (c *Config) SetHoneypotCustomConfig(name string, custom map[string]string) bool {
	c.hpMu.Lock()
	defer c.hpMu.Unlock()
	hp, ok := c.Honeypots[name]
	if !ok {
		return false
	}
	hp.CustomConfig = maps.Clone(custom)
	c.Honeypots[name] = hp
	return true
}

// ReplaceHoneypots makes the honeypot settings those of hps (a snapshot of
// another Config, such as the config file as it is now), under the honeypot
// lock.
func (c *Config) ReplaceHoneypots(hps map[string]HoneypotConfig) {
	c.hpMu.Lock()
	defer c.hpMu.Unlock()
	c.Honeypots = make(map[string]HoneypotConfig, len(hps))
	for name, hp := range hps {
		hp.CustomConfig = maps.Clone(hp.CustomConfig)
		hp.Environment = maps.Clone(hp.Environment)
		c.Honeypots[name] = hp
	}
}

// Clone returns an independent copy of the config, as Parse would read it
// back from the file Save writes.
func (c *Config) Clone() (*Config, error) {
	c.hpMu.RLock()
	data, err := yaml.Marshal(c)
	c.hpMu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to copy config: %w", err)
	}
	return Parse(data, c.ConfigPath)
}

// ResolvedDeviceProfile keeps an automatic choice stable across catalog updates.
// Version identifies the selection algorithm/catalog used when it was resolved.
type ResolvedDeviceProfile struct {
	ID      string `yaml:"id" json:"id"`
	Version int    `yaml:"version" json:"version"`
}

// ConpotDeviceProfile describes one device the pinned Conpot image can emulate.
// Ports describe the container service, not automatically allocated host ports.
type ConpotDeviceProfile struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Model       string   `json:"model"`
	Protocols   []string `json:"protocols"`
	TCP         []int    `json:"tcp_ports"`
	UDP         []int    `json:"udp_ports"`
	Limitations string   `json:"limitations"`
}

const conpotProfileVersion = 1

// This is the active image capability catalog. Adding a profile must not change
// legacyConpotIDs: that immutable order records pre-profile automatic choices.
var conpotDeviceProfiles = []ConpotDeviceProfile{
	{ID: "IEC104", Label: "Substation RTU", Category: "RTU", Model: "Siemens S7-300", Description: "Substation remote terminal unit for utility monitoring and control.", Protocols: []string{"IEC 60870-5-104", "DNP3", "SNMP"}, TCP: []int{2404, 20000}, UDP: []int{161}, Limitations: "Protocol emulation of one RTU; no physical process, HMI or S7comm service."},
	{ID: "guardian_ast", Label: "Fuel tank gauge", Category: "Tank gauge", Model: "Veeder-Root TLS-350", Description: "Tank monitoring endpoint for fuel storage systems.", Protocols: []string{"Tank gauge protocol"}, TCP: []int{10001}, Limitations: "Protocol emulation of one tank gauge; no physical process or HMI simulation."},
	{ID: "ipmi", Label: "Server management controller", Category: "Server management", Model: "Supermicro BMC", Description: "Server baseboard management controller, separate from industrial process control.", Protocols: []string{"IPMI 2.0"}, UDP: []int{623}, Limitations: "Server management protocol emulation; this is not a PLC or RTU."},
	{ID: "kamstrup_382", Label: "Electricity meter", Category: "Meter", Model: "Kamstrup 382", Description: "Electricity meter with metering and management interfaces.", Protocols: []string{"Kamstrup metering", "Kamstrup management"}, TCP: []int{1025, 50100}, Limitations: "Protocol emulation of one meter; no physical power system simulation."},
	{ID: "beckhoff_cx", Label: "Industrial PLC", Category: "PLC", Model: "Beckhoff CX5140 / TwinCAT 3", Description: "Industrial controller with OPC UA and ADS interfaces.", Protocols: []string{"OPC UA", "ADS"}, TCP: []int{4840, 48898}, UDP: []int{48899}, Limitations: "Protocol emulation of one controller; no physical process, TwinCAT runtime or HMI simulation."},
	{ID: "building_automation", Label: "Building automation controller", Category: "Building controller", Model: "LOYTEC LINX-153", Description: "Building control endpoint for BACnet and KNX networks.", Protocols: []string{"BACnet/IP", "KNXnet/IP"}, UDP: []int{3671, 47808}, Limitations: "Protocol emulation of one building controller; no building process or HMI simulation."},
	{ID: "hart_gateway", Label: "WirelessHART gateway", Category: "Gateway", Model: "Emerson 1420", Description: "Industrial field instrumentation gateway exposed through HART-IP.", Protocols: []string{"HART-IP"}, TCP: []int{5094}, Limitations: "HART-IP protocol emulation; no wireless radio or physical instruments."},
	{ID: "iccp", Label: "Utility communications server", Category: "Utility server", Model: "SISCO ICCP / TASE.2", Description: "Control-center communications endpoint for utilities.", Protocols: []string{"ICCP / TASE.2"}, TCP: []int{102}, Limitations: "Protocol emulation of one server; TCP 102 does not imply S7comm support."},
	{ID: "plc_modbus", Label: "Modbus PLC", Category: "PLC", Model: "Schneider Modicon M340", Description: "Programmable logic controller exposed through Modbus/TCP.", Protocols: []string{"Modbus/TCP"}, TCP: []int{502}, Limitations: "Protocol emulation of one PLC; no physical process, engineering workstation or HMI simulation."},
}

// legacyConpotIDs is intentionally independent of the active catalog. It is a
// migration contract: never append, remove or reorder entries here.
var legacyConpotIDs = [...]string{"IEC104", "guardian_ast", "ipmi", "kamstrup_382", "beckhoff_cx", "building_automation", "hart_gateway", "iccp", "plc_modbus"}

// ConpotProfiles returns independent copies of the supported device profiles.
func ConpotProfiles() []ConpotDeviceProfile {
	out := slices.Clone(conpotDeviceProfiles)
	for i := range out {
		out[i].Protocols = slices.Clone(out[i].Protocols)
		out[i].TCP = slices.Clone(out[i].TCP)
		out[i].UDP = slices.Clone(out[i].UDP)
	}
	return out
}

func conpotProfileKnown(id string) bool {
	return slices.ContainsFunc(conpotDeviceProfiles, func(p ConpotDeviceProfile) bool { return p.ID == id })
}

// legacyConpotProfileID reproduces the pre-profile selection exactly. It is
// also the default for unsaved configurations; it never writes during a read.
func legacyConpotProfileID(c *Config) string {
	id := c.QPotID
	if id == "" {
		id = c.InstanceName
	}
	sum := sha256.Sum256([]byte("qpot-deception-seed-v1\x00" + id))
	seed := "ds_" + hex.EncodeToString(sum[:16])
	h := fnv.New32a()
	_, _ = h.Write([]byte("tpot-conpot:" + seed))
	return legacyConpotIDs[h.Sum32()%uint32(len(legacyConpotIDs))]
}

// ConpotAutomaticProfileID returns the saved automatic choice, or the legacy
// choice before first save. A custom_config template pin is intentionally not
// consulted: clearing it must restore the same automatic device.
func ConpotAutomaticProfileID(c *Config) string {
	if hp, ok := c.GetHoneypotConfig("conpot"); ok && hp.DeviceProfile.ID != "" {
		return hp.DeviceProfile.ID
	}
	return legacyConpotProfileID(c)
}

// resolveDeviceProfiles validates saved selections. Only Save resolves a
// missing selection: Parse callers may replace a stale YAML credential with
// the canonical runtime identity before that choice can safely be frozen.
func (c *Config) resolveDeviceProfiles(resolveMissing bool) error {
	c.hpMu.Lock()
	defer c.hpMu.Unlock()
	if hp, ok := c.Honeypots["refrigeration"]; ok {
		if profile := strings.TrimSpace(hp.CustomConfig["site_profile"]); profile != "" && profile != "retail" && profile != "plasma" {
			return fmt.Errorf("honeypots.refrigeration.custom_config.site_profile %q is unsupported; use retail or plasma", profile)
		}
	}
	hp, ok := c.Honeypots["conpot"]
	if !ok {
		return nil
	}
	if pin := strings.TrimSpace(hp.CustomConfig["template"]); pin != "" && !conpotProfileKnown(pin) {
		return fmt.Errorf("honeypots.conpot.custom_config.template %q is unsupported; choose a supported device with qpot honeypot profiles conpot", pin)
	}
	p := hp.DeviceProfile
	if p.ID == "" && p.Version == 0 {
		// The runtime may replace a stale YAML identity after Parse. Leave
		// the choice unresolved until Save sees the final runtime identity.
		if !resolveMissing {
			return nil
		}
		p = ResolvedDeviceProfile{ID: legacyConpotProfileID(c), Version: conpotProfileVersion}
	} else if p.Version != conpotProfileVersion || !conpotProfileKnown(p.ID) {
		return fmt.Errorf("honeypots.conpot.device_profile has unsupported id %q or version %d; restore a supported saved profile instead of changing the device silently", p.ID, p.Version)
	}
	hp.DeviceProfile = p
	c.Honeypots["conpot"] = hp
	return nil
}

func defaultRefrigerationConfig() HoneypotConfig {
	return HoneypotConfig{
		Enabled: false, Port: 8080, RiskLevel: "low", Sandbox: true,
		Resources: HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 20, MaxMemoryMB: 128, MaxPids: 50},
	}
}
