package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/geo"
	"github.com/qpot/qpot/internal/hostsetup"
)

// setupAnswers are the settings a new instance is created with: asked in a
// terminal, or taken from flags and defaults.
type setupAnswers struct {
	Instance  string   `json:"instance"`
	Profile   string   `json:"profile"` // minimal, standard, hifi or custom
	Honeypots []string `json:"honeypots"`
	Bind      string   `json:"bind"`
	Port      int      `json:"port"`
	Country   string   `json:"country"`
	GeoIP     bool     `json:"geoip"`
	Database  string   `json:"database"`
	Outbound  string   `json:"outbound"` // allow or block
	Service   bool     `json:"service"`
}

// defaultAnswers are the recommended settings.
func defaultAnswers() setupAnswers {
	return setupAnswers{
		Instance:  "default",
		Profile:   "minimal",
		Honeypots: append([]string(nil), setupProfiles["minimal"]...),
		Bind:      "127.0.0.1",
		Port:      8080,
		GeoIP:     true,
		Database:  "clickhouse",
		Outbound:  "allow",
	}
}

// knownHoneypots are the honeypot names QPot ships, sorted.
func knownHoneypots() []string {
	var names []string
	for n := range config.Default("x").Honeypots {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// parseInstanceAnswer checks an instance name.
func parseInstanceAnswer(s string) (string, *hostsetup.Error) {
	s = strings.TrimSpace(s)
	if err := validateInstanceName(s); err != nil {
		return "", hostsetup.E("QP-INPUT-001").WithWhy("%q is not a valid instance name: use 1 to 32 letters, digits, '-' or '_', starting with a letter or digit.", truncRunes(s, 40))
	}
	return s, nil
}

// parseHoneypotsAnswer accepts a profile name (minimal, standard, hifi) or a
// list of honeypot names separated by commas or spaces. It returns the
// profile ("custom" for a list) and the sorted, de-duplicated names.
func parseHoneypotsAnswer(s string) (string, []string, *hostsetup.Error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 1024 {
		return "", nil, hostsetup.E("QP-INPUT-003").WithWhy("The list is too long.")
	}
	if hps, ok := setupProfiles[s]; ok {
		return s, append([]string(nil), hps...), nil
	}
	known := map[string]bool{}
	for _, n := range knownHoneypots() {
		known[n] = true
	}
	seen := map[string]bool{}
	var out []string
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' })
	for _, f := range fields {
		if !known[f] {
			if len(fields) == 1 {
				return "", nil, hostsetup.E("QP-INPUT-002").WithWhy("%q is neither a profile (minimal, standard, hifi) nor a honeypot QPot knows.", truncRunes(f, 40))
			}
			return "", nil, hostsetup.E("QP-INPUT-003").WithWhy("%q is not a honeypot QPot knows.", truncRunes(f, 40))
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return "", nil, hostsetup.E("QP-INPUT-003").WithWhy("No honeypot was named.")
	}
	sort.Strings(out)
	// A list that is exactly a profile is called by the profile's name.
	for _, name := range []string{"minimal", "standard", "hifi"} {
		if strings.Join(sortedCopy(setupProfiles[name]), ",") == strings.Join(out, ",") {
			return name, out, nil
		}
	}
	return "custom", out, nil
}

// parsePortAnswer checks a port number (1-65535, digits only).
func parsePortAnswer(s string) (int, *hostsetup.Error) {
	s = strings.TrimSpace(s)
	bad := hostsetup.E("QP-INPUT-004").WithWhy("%q is not a port number from 1 to 65535.", truncRunes(s, 20))
	if s == "" || len(s) > 5 {
		return 0, bad
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, bad
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, bad
	}
	return n, nil
}

// bindExposure says who can reach a web UI bound to an address.
type bindExposure int

const (
	bindLocal   bindExposure = iota // loopback: this computer only
	bindAll                         // every network the computer is on
	bindNetwork                     // one network address
)

// parseBindAnswer checks a web UI bind address: an IP literal that is
// loopback, unspecified (all interfaces) or one of this computer's own
// addresses. "localhost" means 127.0.0.1. Host names are refused: what they
// resolve to can change.
func parseBindAnswer(s string, local []netip.Addr) (string, bindExposure, *hostsetup.Error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "localhost") {
		return "127.0.0.1", bindLocal, nil
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", 0, hostsetup.E("QP-INPUT-005").WithWhy("%q is not an IP address (use for example 127.0.0.1 or 0.0.0.0).", truncRunes(s, 45))
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return a.String(), bindLocal, nil
	case a.IsUnspecified():
		return a.String(), bindAll, nil
	case a.IsMulticast() || a.IsInterfaceLocalMulticast():
		return "", 0, hostsetup.E("QP-INPUT-005").WithWhy("%s is a multicast address; the web UI needs an address of this computer.", a)
	}
	for _, l := range local {
		if l.Unmap() == a {
			return a.String(), bindNetwork, nil
		}
	}
	return "", 0, hostsetup.E("QP-INPUT-005").WithWhy("%s is not an address of this computer.", a)
}

// localAddrs returns this computer's interface addresses.
func localAddrs() []netip.Addr {
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}

// parseCountryAnswer checks an ISO country code; "", "none" or "skip" keep
// the default (the time zone's country).
func parseCountryAnswer(s string) (string, *hostsetup.Error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "none", "skip", "auto":
		return "", nil
	}
	c, ok := geo.Lookup(s)
	if !ok {
		return "", hostsetup.E("QP-INPUT-006").WithWhy("%q is not a two-letter country code QPot knows.", truncRunes(s, 20))
	}
	return c.Code, nil
}

func parseDatabaseAnswer(s string) (string, *hostsetup.Error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "clickhouse", "timescaledb":
		return v, nil
	}
	return "", hostsetup.E("QP-INPUT-007").WithWhy("%q is not a database QPot supports (clickhouse or timescaledb).", truncRunes(s, 30))
}

func parseOutboundAnswer(s string) (string, *hostsetup.Error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "allow", "block":
		return v, nil
	}
	return "", hostsetup.E("QP-INPUT-012").WithWhy("%q is not allow or block.", truncRunes(s, 30)).
		WithFix("Use --outbound allow (honeypots may download what attackers fetch; your own network stays blocked) or --outbound block.")
}

func parseDockerSource(s string) (string, *hostsetup.Error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "auto", "docker", "distro":
		return v, nil
	}
	return "", hostsetup.E("QP-INPUT-012").WithWhy("%q is not auto, docker or distro.", truncRunes(s, 30)).
		WithFix("Use --docker-source auto (the default), docker (Docker's repository) or distro (the distribution's packages).")
}

// parseYesNo reads a yes/no answer; "" means the default.
func parseYesNo(s string, def bool) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return def, true
	case "y", "yes":
		return true, true
	case "n", "no":
		return false, true
	}
	return false, false
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// applyAnswers writes answers into a new instance's config.
func applyAnswers(cfg *config.Config, a setupAnswers) {
	want := map[string]bool{}
	for _, h := range a.Honeypots {
		want[h] = true
	}
	for name := range cfg.SnapshotHoneypots() {
		if !want[name] {
			cfg.DisableHoneypot(name)
		}
	}
	for _, h := range a.Honeypots {
		cfg.EnableHoneypot(h)
	}
	cfg.WebUI.BindAddr = a.Bind
	cfg.WebUI.Port = a.Port
	cfg.Ports.WebUIPort = a.Port
	if a.Database != "" {
		cfg.Database.Type = a.Database
	}
	cfg.Security.NetworkIsolation.BlockOutbound = a.Outbound == "block"
	if a.Country != "" {
		cfg.AttackMap.Country = a.Country
	}
}

// setupStatePath is where answers for an instance that does not exist yet
// are kept, so setup run again after a failure can offer them.
func setupStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".qpot", "setup-answers.json")
}

func saveSetupState(a setupAnswers) error {
	p := setupStatePath()
	if p == "" {
		return errors.New("no home directory")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// loadSetupState returns saved answers, re-checked: a damaged or edited
// file is ignored rather than trusted.
func loadSetupState() (setupAnswers, bool) {
	p := setupStatePath()
	if p == "" {
		return setupAnswers{}, false
	}
	data, err := os.ReadFile(p) // #nosec G304 -- fixed path under the home directory
	if err != nil || len(data) > 64<<10 {
		return setupAnswers{}, false
	}
	var a setupAnswers
	if json.Unmarshal(data, &a) != nil {
		return setupAnswers{}, false
	}
	if _, err := parseInstanceAnswer(a.Instance); err != nil {
		return setupAnswers{}, false
	}
	prof, hps, herr := parseHoneypotsAnswer(strings.Join(a.Honeypots, ","))
	if herr != nil {
		return setupAnswers{}, false
	}
	a.Honeypots = hps
	if a.Profile != "custom" {
		if want, ok := setupProfiles[a.Profile]; !ok || strings.Join(sortedCopy(want), ",") != strings.Join(hps, ",") {
			a.Profile = prof
		}
	}
	if _, _, err := parseBindAnswer(a.Bind, localAddrs()); err != nil {
		return setupAnswers{}, false
	}
	if a.Port < 1 || a.Port > 65535 {
		return setupAnswers{}, false
	}
	if _, err := parseCountryAnswer(a.Country); err != nil {
		return setupAnswers{}, false
	}
	if _, err := parseDatabaseAnswer(a.Database); err != nil {
		return setupAnswers{}, false
	}
	if _, err := parseOutboundAnswer(a.Outbound); err != nil {
		return setupAnswers{}, false
	}
	return a, true
}

func clearSetupState() {
	if p := setupStatePath(); p != "" {
		_ = os.Remove(p)
	}
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}
