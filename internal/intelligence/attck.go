// Package intelligence provides threat intelligence classification for QPot.
package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// attckURL is the MITRE ATT&CK enterprise STIX bundle.
const attckURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

// attckCacheFile is the name of the locally cached STIX bundle.
const attckCacheFile = "attck-enterprise.json"

// Technique represents a MITRE ATT&CK technique.
type Technique struct {
	ID             string
	SubID          string // e.g. "T1110.001"
	Name           string
	TacticIDs      []string
	TacticNames    []string
	Description    string
	URL            string
	Detection      string   // x_mitre_detection text
	DataSources    []string // x_mitre_data_sources
	Platforms      []string // x_mitre_platforms
	IsSubTechnique bool     // x_mitre_is_subtechnique
	Keywords       []string // extracted from name + description + detection
}

// ATTCKLoader loads and caches ATT&CK technique data.
type ATTCKLoader struct {
	techniques map[string]*Technique // keyed by SubID or ID
	dataPath   string                // where to cache the downloaded JSON
	loaded     bool                  // true when data loaded beyond embedded fallback
}

// NewATTCKLoader returns an ATTCKLoader that caches data under dataPath.
func NewATTCKLoader(dataPath string) *ATTCKLoader {
	return &ATTCKLoader{
		techniques: make(map[string]*Technique),
		dataPath:   dataPath,
	}
}

// Loaded reports whether ATT&CK data was loaded from the network or cache
// (true), or only from the embedded fallback (false).
func (a *ATTCKLoader) Loaded() bool {
	return a.loaded
}

// Load tries to fetch latest from MITRE GitHub, falls back to cached file,
// then falls back to the embedded minimal technique map.
// It never returns an error — the caller always gets at least the embedded data.
func (a *ATTCKLoader) Load(ctx context.Context) {
	// Try network fetch first.
	if err := a.fetchFromNetwork(ctx); err == nil {
		a.loaded = true
		slog.Info("ATT&CK data loaded from MITRE GitHub", "techniques", len(a.techniques))
		return
	}

	// Try cached file.
	cachePath := filepath.Join(a.dataPath, attckCacheFile)
	if err := a.loadFromFile(cachePath); err == nil {
		a.loaded = true
		slog.Info("ATT&CK data loaded from cache", "path", cachePath, "techniques", len(a.techniques))
		return
	}

	// Fall back to embedded minimal map.
	a.loadEmbedded()
	slog.Info("ATT&CK data loaded from embedded fallback", "techniques", len(a.techniques))
}

// Get returns a technique by ID (e.g. "T1110" or "T1110.001").
func (a *ATTCKLoader) Get(id string) (*Technique, bool) {
	t, ok := a.techniques[strings.ToUpper(id)]
	return t, ok
}

// fetchFromNetwork downloads the STIX bundle and caches it to disk.
func (a *ATTCKLoader) fetchFromNetwork(ctx context.Context) error {
	httpCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodGet, attckURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if err := a.parseSTIX(data); err != nil {
		return fmt.Errorf("parse STIX: %w", err)
	}

	// Cache to disk (best-effort).
	if err := os.MkdirAll(a.dataPath, 0750); err == nil {
		_ = os.WriteFile(filepath.Join(a.dataPath, attckCacheFile), data, 0640)
	}

	return nil
}

// loadFromFile loads the cached STIX bundle from disk.
func (a *ATTCKLoader) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return a.parseSTIX(data)
}

// stixBundle is the minimal structure needed to parse the STIX bundle.
type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type               string               `json:"type"`
	Name               string               `json:"name"`
	Description        string               `json:"description"`
	ExternalReferences []stixExtRef         `json:"external_references"`
	KillChainPhases    []stixKillChainPhase `json:"kill_chain_phases"`
	Revoked            bool                 `json:"revoked"`
	Deprecated         bool                 `json:"x_mitre_deprecated"`
	ShortName          string               `json:"x_mitre_shortname"` // x-mitre-tactic: "persistence"
	Detection          string               `json:"x_mitre_detection"`
	DataSources        []string             `json:"x_mitre_data_sources"`
	Platforms          []string             `json:"x_mitre_platforms"`
	IsSubTechnique     bool                 `json:"x_mitre_is_subtechnique"`
}

type stixExtRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url"`
}

type stixKillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// reBacktick matches the code spans of an ATT&CK description, the only part
// of its prose that names a concrete command or setting.
var reBacktick = regexp.MustCompile("`([^`\n]+)`")

// Code terms a generated rule can match. A command term is a lower-case
// command name, optionally with fixed arguments ("useradd", "crontab -l",
// "export HISTFILESIZE=0"); it matches only where a shell runs it, so
// "man useradd" is not account creation. An identifier term is a setting or
// symbol name with a capital letter or an underscore ("HISTFILE",
// "ExecStart", "PermitRootLogin"); it matches as a whole word, case and all.
//
// Nothing else in a code span becomes a matcher: not the technique's name
// (English words: "Windows 7 or 8" is not Application Window Discovery), not
// paths, file names or extensions (they say what a technique touches, not
// what it does: reading /var/log/kern.log is not clearing it), and not
// Windows syntax or placeholders such as /proc/<PID>/maps.
var (
	reCommandTerm    = regexp.MustCompile(`^[a-z][a-z0-9_+-]*(?: [A-Za-z0-9_./=+:-]+)*$`)
	reIdentifierTerm = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// contextCommands are everyday commands ATT&CK cites as context ("ps and top
// show the process", "a hook in sshd", "delay with sleep or ping") rather
// than as the technique itself. A command term starting with one names no
// technique on its own.
var contextCommands = map[string]bool{
	"cat": true, "ls": true, "ps": true, "top": true, "rm": true, "cp": true, "mv": true,
	"cd": true, "echo": true, "printf": true, "grep": true, "find": true, "touch": true,
	"mkdir": true, "chmod": true, "chown": true, "sleep": true, "ping": true, "kill": true,
	"init": true, "hash": true, "mount": true, "ssh": true, "sshd": true, "iptables": true,
	"dmesg": true, "ldd": true, "curl": true, "wget": true, "bash": true, "sh": true,
	"python": true, "perl": true, "sudo": true, "su": true, "env": true, "uname": true,
	"id": true, "whoami": true, "hostname": true, "ifconfig": true, "ip": true,
	"netstat": true, "df": true, "du": true, "tar": true, "base64": true, "source": true,
	"which": true, "type": true, "open": true, "copy": true, "dir": true, "import": true,
}

// Term kinds returned by codeTerm.
const (
	termNone = iota
	termCommand
	termIdentifier
)

// maxDynamicTerms bounds the alternation of one generated rule.
const maxDynamicTerms = 10

// codeTerm reports whether a code span can identify a technique in a captured
// shell command, and how: the span with its spacing normalised and its kind.
func codeTerm(span string) (string, int) {
	term := strings.Join(strings.Fields(span), " ")
	if len(term) < 4 {
		return "", termNone
	}
	if reIdentifierTerm.MatchString(term) && strings.ContainsAny(term, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") {
		return term, termIdentifier
	}
	if reCommandTerm.MatchString(term) {
		if first, _, _ := strings.Cut(term, " "); !contextCommands[first] {
			return term, termCommand
		}
	}
	return "", termNone
}

// codeSpans returns the distinct code spans of text, normalised.
func codeSpans(text string) []string {
	var spans []string
	seen := make(map[string]bool)
	for _, m := range reBacktick.FindAllStringSubmatch(text, -1) {
		s := strings.Join(strings.Fields(m[1]), " ")
		if s != "" && !seen[s] {
			seen[s] = true
			spans = append(spans, s)
		}
	}
	return spans
}

const (
	// cmdStart is where a shell runs a command: the start of the input or of
	// a list or pipeline element, behind optional wrappers (with their
	// flags) and an optional directory, as in "busybox nohup ./x" or
	// "/usr/sbin/useradd".
	cmdStart = `(?:^|[\n;&|(\x60]|\$\()\s*(?:(?:sudo|busybox|nohup|exec|command|nice|setsid)(?:\s+-\S+)*\s+)*(?:[\w.~-]*/)*`
	// cmdEnd ends the command word or its fixed arguments.
	cmdEnd = `(?:$|[\s;&|)\x60<>])`
)

// dynamicPattern builds the command-field pattern matching terms, or "".
func dynamicPattern(terms []string) string {
	var cmds, ids []string
	for _, term := range terms {
		t, kind := codeTerm(term)
		switch kind {
		case termCommand:
			words := strings.Fields(t)
			for i, w := range words {
				words[i] = regexp.QuoteMeta(w)
			}
			cmds = append(cmds, strings.Join(words, `\s+`))
		case termIdentifier:
			ids = append(ids, regexp.QuoteMeta(t))
		}
	}
	var alts []string
	if len(cmds) > 0 {
		alts = append(alts, cmdStart+"(?:"+strings.Join(cmds, "|")+")"+cmdEnd)
	}
	if len(ids) > 0 {
		alts = append(alts, `(?:^|\W)(?:`+strings.Join(ids, "|")+`)(?:$|\W)`)
	}
	return strings.Join(alts, "|")
}

// parseSTIX parses a STIX 2.x bundle and populates the techniques map.
func (a *ATTCKLoader) parseSTIX(data []byte) error {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}

	// Tactic IDs by short name ("persistence" -> "TA0003").
	tacticIDs := make(map[string]string)
	for _, obj := range bundle.Objects {
		if obj.Type != "x-mitre-tactic" || obj.ShortName == "" {
			continue
		}
		for _, ref := range obj.ExternalReferences {
			if ref.SourceName == "mitre-attack" {
				tacticIDs[obj.ShortName] = ref.ExternalID
				break
			}
		}
	}

	spans := make(map[*Technique][]string)
	citedBy := make(map[string]int) // lower-cased code span -> techniques citing it
	count := 0
	for _, obj := range bundle.Objects {
		// A deprecated technique is no longer part of ATT&CK (v18 still
		// ships T1153 "Source"); a revoked one was replaced.
		if obj.Type != "attack-pattern" || obj.Revoked || obj.Deprecated {
			continue
		}

		// Find MITRE ATT&CK external ID.
		var techID, techURL string
		for _, ref := range obj.ExternalReferences {
			if ref.SourceName == "mitre-attack" {
				techID = ref.ExternalID
				techURL = ref.URL
				break
			}
		}
		if techID == "" {
			continue
		}

		// Collect tactic names and IDs from kill chain phases.
		var tacticNames, tacticIDList []string
		for _, kcp := range obj.KillChainPhases {
			if kcp.KillChainName == "mitre-attack" || kcp.KillChainName == "mitre-ics-attack" {
				tacticNames = append(tacticNames, kcp.PhaseName)
				tacticIDList = append(tacticIDList, tacticIDs[kcp.PhaseName])
			}
		}

		tech := &Technique{
			ID:             techID,
			SubID:          techID,
			Name:           obj.Name,
			TacticIDs:      tacticIDList,
			TacticNames:    tacticNames,
			Description:    truncate(obj.Description, 512),
			URL:            techURL,
			Detection:      truncate(obj.Detection, 1024),
			DataSources:    obj.DataSources,
			Platforms:      obj.Platforms,
			IsSubTechnique: obj.IsSubTechnique,
		}

		// Code spans of the full description and detection text (ATT&CK v18
		// dropped x_mitre_detection; older bundles still carry it).
		ss := codeSpans(obj.Description + "\n" + obj.Detection)
		seen := make(map[string]bool)
		for _, s := range ss {
			if k := strings.ToLower(s); !seen[k] {
				seen[k] = true
				citedBy[k]++
			}
		}
		spans[tech] = ss
		a.techniques[techID] = tech
		count++
	}

	// Keywords are the code terms only this technique cites: a command
	// several techniques mention (curl, systemctl, LD_PRELOAD) cannot say
	// which one an attacker performed.
	for tech, ss := range spans {
		for _, s := range ss {
			if citedBy[strings.ToLower(s)] != 1 {
				continue
			}
			if term, kind := codeTerm(s); kind != termNone && len(tech.Keywords) < maxDynamicTerms {
				tech.Keywords = append(tech.Keywords, term)
			}
		}
	}

	if count == 0 {
		return fmt.Errorf("no attack-pattern objects found in bundle")
	}
	return nil
}

// tacticToKillChain maps ATT&CK tactic phase names to QPot kill chain stages.
// ATT&CK v18 split defense-evasion into stealth and defense-impairment.
var tacticToKillChain = map[string]string{
	"credential-access":      "initial-access",
	"execution":              "execution",
	"discovery":              "discovery",
	"persistence":            "persistence",
	"privilege-escalation":   "privilege-escalation",
	"lateral-movement":       "c2",
	"collection":             "collection",
	"exfiltration":           "exfiltration",
	"command-and-control":    "c2",
	"initial-access":         "initial-access",
	"defense-evasion":        "execution",
	"stealth":                "execution",
	"defense-impairment":     "execution",
	"impact":                 "exfiltration",
	"reconnaissance":         "reconnaissance",
	"resource-development":   "reconnaissance",
	"impair-process-control": "initial-access",
}

// GenerateDynamicRules generates classification rules for all loaded techniques
// that are not embedded-only. Returns nil when only the embedded fallback is
// loaded (those techniques lack detection metadata for meaningful rules).
// The rules are sorted by technique ID: they share one priority, so their
// order decides which one labels a command two of them match.
func (a *ATTCKLoader) GenerateDynamicRules() []Rule {
	if !a.loaded {
		// Embedded fallback has no detection metadata — skip dynamic generation.
		return nil
	}

	var rules []Rule
	for _, tech := range a.techniques {
		rule := buildDynamicRule(tech)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].TechniqueID < rules[j].TechniqueID })
	return rules
}

// buildDynamicRule constructs a single Rule from a Technique's metadata.
// Returns nil when the technique should be skipped (wrong platform, no
// usable code term). The rule applies to shell input only: sensor text in
// the command field (a Suricata signature, a p0f OS name, a JA3 hash) and
// SMTP dialogue are not commands.
func buildDynamicRule(t *Technique) *Rule {
	// Platform filter: skip techniques that only target Windows with no
	// cross-platform applicability. Techniques with empty platforms are also
	// skipped (embedded fallback — no metadata).
	if len(t.Platforms) == 0 {
		return nil
	}
	onlyWindows := true
	for _, p := range t.Platforms {
		switch strings.ToLower(p) {
		case "linux", "macos", "network", "network devices", "containers", "esxi":
			onlyWindows = false
		}
	}
	if onlyWindows {
		return nil
	}

	pattern := dynamicPattern(t.Keywords)
	if pattern == "" {
		return nil
	}

	// Tactic info from first tactic.
	tacticName := ""
	if len(t.TacticNames) > 0 {
		tacticName = t.TacticNames[0]
	}
	tacticID := ""
	if len(t.TacticIDs) > 0 {
		tacticID = t.TacticIDs[0]
	}
	killChain := tacticToKillChain[tacticName]
	if killChain == "" {
		killChain = "execution"
	}

	return &Rule{
		TechniqueID: t.SubID,
		TacticID:    tacticID,
		TacticName:  tacticName,
		Name:        t.Name,
		KillChain:   killChain,
		Honeypots:   []string{},
		Priority:    10,
		Conditions: []Condition{
			{Field: "event_type", Pattern: `command`},
			{Field: "command", Pattern: pattern},
		},
		Confidence: 0.6,
	}
}

// loadEmbedded populates techniques with the hardcoded minimal map.
func (a *ATTCKLoader) loadEmbedded() {
	embedded := []*Technique{
		{
			ID: "T1046", SubID: "T1046", Name: "Network Service Discovery",
			TacticIDs: []string{"TA0007"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T1046/",
		},
		{
			ID: "T1110", SubID: "T1110", Name: "Brute Force",
			TacticIDs: []string{"TA0006"}, TacticNames: []string{"credential-access"},
			URL: "https://attack.mitre.org/techniques/T1110/",
		},
		{
			ID: "T1110", SubID: "T1110.001", Name: "Password Guessing",
			TacticIDs: []string{"TA0006"}, TacticNames: []string{"credential-access"},
			URL: "https://attack.mitre.org/techniques/T1110/001/",
		},
		{
			ID: "T1110", SubID: "T1110.003", Name: "Password Spraying",
			TacticIDs: []string{"TA0006"}, TacticNames: []string{"credential-access"},
			URL: "https://attack.mitre.org/techniques/T1110/003/",
		},
		{
			ID: "T1110", SubID: "T1110.004", Name: "Credential Stuffing",
			TacticIDs: []string{"TA0006"}, TacticNames: []string{"credential-access"},
			URL: "https://attack.mitre.org/techniques/T1110/004/",
		},
		{
			ID: "T1105", SubID: "T1105", Name: "Ingress Tool Transfer",
			TacticIDs: []string{"TA0011"}, TacticNames: []string{"command-and-control"},
			URL: "https://attack.mitre.org/techniques/T1105/",
		},
		{
			ID: "T1059", SubID: "T1059", Name: "Command and Scripting Interpreter",
			TacticIDs: []string{"TA0002"}, TacticNames: []string{"execution"},
			URL: "https://attack.mitre.org/techniques/T1059/",
		},
		{
			ID: "T1059", SubID: "T1059.004", Name: "Unix Shell",
			TacticIDs: []string{"TA0002"}, TacticNames: []string{"execution"},
			URL: "https://attack.mitre.org/techniques/T1059/004/",
		},
		{
			ID: "T1082", SubID: "T1082", Name: "System Information Discovery",
			TacticIDs: []string{"TA0007"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T1082/",
		},
		{
			ID: "T1033", SubID: "T1033", Name: "System Owner/User Discovery",
			TacticIDs: []string{"TA0007"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T1033/",
		},
		{
			ID: "T1016", SubID: "T1016", Name: "System Network Configuration Discovery",
			TacticIDs: []string{"TA0007"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T1016/",
		},
		{
			ID: "T1049", SubID: "T1049", Name: "System Network Connections Discovery",
			TacticIDs: []string{"TA0007"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T1049/",
		},
		{
			ID: "T1548", SubID: "T1548", Name: "Abuse Elevation Control Mechanism",
			TacticIDs: []string{"TA0004"}, TacticNames: []string{"privilege-escalation"},
			URL: "https://attack.mitre.org/techniques/T1548/",
		},
		{
			ID: "T1053", SubID: "T1053", Name: "Scheduled Task/Job",
			TacticIDs: []string{"TA0003"}, TacticNames: []string{"persistence"},
			URL: "https://attack.mitre.org/techniques/T1053/",
		},
		{
			ID: "T1190", SubID: "T1190", Name: "Exploit Public-Facing Application",
			TacticIDs: []string{"TA0001"}, TacticNames: []string{"initial-access"},
			URL: "https://attack.mitre.org/techniques/T1190/",
		},
		{
			ID: "T0840", SubID: "T0840", Name: "Network Connection Enumeration",
			TacticIDs: []string{"TA0102"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T0840/",
		},
		{
			ID: "T0846", SubID: "T0846", Name: "Remote System Discovery",
			TacticIDs: []string{"TA0102"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T0846/",
		},
		{
			ID: "T0855", SubID: "T0855", Name: "Unauthorized Command Message",
			TacticIDs: []string{"TA0104"}, TacticNames: []string{"impair-process-control"},
			URL: "https://attack.mitre.org/techniques/T0855/",
		},
	}

	for _, t := range embedded {
		a.techniques[t.SubID] = t
	}
}

// truncate shortens s to at most n runes.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
