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

// reBacktick matches terms inside backticks.
var reBacktick = regexp.MustCompile("`([^`]+)`")

// reQuoted matches quoted terms 2-30 chars long.
var reQuoted = regexp.MustCompile(`"([^"]{2,30})"`)

// stopwords is a set of common English words to exclude from keywords.
var stopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true,
	"this": true, "are": true, "from": true, "may": true, "can": true,
	"use": true, "used": true, "such": true, "also": true, "has": true,
	"have": true, "been": true, "when": true, "their": true, "they": true,
	"using": true, "will": true, "which": true, "more": true, "than": true,
	"these": true, "into": true, "other": true, "system": true, "not": true,
	"its": true, "all": true, "any": true, "via": true, "often": true,
	"both": true, "well": true, "each": true, "through": true, "about": true,
	"data": true, "log": true, "logs": true, "file": true, "files": true,
	"user": true, "users": true, "access": true, "attack": true,
	"monitor": true, "activity": true, "malicious": true, "content": true,
}

// ExtractKeywords extracts meaningful technical keywords from text.
// It lowercases input, pulls out backtick/quoted terms, and filters stopwords.
func ExtractKeywords(text string) []string {
	text = strings.ToLower(text)
	seen := make(map[string]bool)
	var keywords []string

	addKW := func(w string) {
		w = strings.TrimSpace(w)
		if len(w) < 3 {
			return
		}
		if stopwords[w] {
			return
		}
		if !seen[w] {
			seen[w] = true
			keywords = append(keywords, w)
		}
	}

	// Extract backtick-quoted terms first (highest specificity).
	for _, m := range reBacktick.FindAllStringSubmatch(text, -1) {
		addKW(m[1])
	}

	// Extract double-quoted terms.
	for _, m := range reQuoted.FindAllStringSubmatch(text, -1) {
		addKW(m[1])
	}

	// Extract individual words (alpha + digits + hyphens, no pure numbers).
	for _, word := range strings.FieldsFunc(text, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.'
	}) {
		// Skip pure numbers and overly long words.
		if len(word) > 50 {
			continue
		}
		allDigit := true
		for _, ch := range word {
			if ch < '0' || ch > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			continue
		}
		addKW(word)
	}

	return keywords
}

// parseSTIX parses a STIX 2.x bundle and populates the techniques map.
func (a *ATTCKLoader) parseSTIX(data []byte) error {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}

	count := 0
	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" || obj.Revoked {
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

		// Collect tactic names from kill chain phases.
		var tacticNames []string
		for _, kcp := range obj.KillChainPhases {
			if kcp.KillChainName == "mitre-attack" || kcp.KillChainName == "mitre-ics-attack" {
				tacticNames = append(tacticNames, kcp.PhaseName)
			}
		}

		// Extract keywords from name + detection text + data sources.
		kwText := obj.Name + " " + obj.Detection
		for _, ds := range obj.DataSources {
			// e.g. "Command: Windows Command Shell" → extract "command"
			parts := strings.SplitN(ds, ":", 2)
			kwText += " " + strings.TrimSpace(parts[0])
		}
		keywords := ExtractKeywords(kwText)

		tech := &Technique{
			ID:             techID,
			SubID:          techID,
			Name:           obj.Name,
			TacticNames:    tacticNames,
			Description:    truncate(obj.Description, 512),
			URL:            techURL,
			Detection:      truncate(obj.Detection, 1024),
			DataSources:    obj.DataSources,
			Platforms:      obj.Platforms,
			IsSubTechnique: obj.IsSubTechnique,
			Keywords:       keywords,
		}

		a.techniques[techID] = tech
		count++
	}

	if count == 0 {
		return fmt.Errorf("no attack-pattern objects found in bundle")
	}
	return nil
}

// tacticToKillChain maps ATT&CK tactic phase names to QPot kill chain stages.
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
	"impact":                 "exfiltration",
	"reconnaissance":         "reconnaissance",
	"resource-development":   "reconnaissance",
	"impair-process-control": "initial-access",
}

// GenerateDynamicRules generates classification rules for all loaded techniques
// that are not embedded-only. Returns nil when only the embedded fallback is
// loaded (those techniques lack detection metadata for meaningful rules).
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
	return rules
}

// buildDynamicRule constructs a single Rule from a Technique's metadata.
// Returns nil when the technique should be skipped (wrong platform, no keywords).
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
		case "linux", "macos", "network", "containers":
			onlyWindows = false
		}
	}
	if onlyWindows {
		return nil
	}

	// Gather keywords: prefer shorter, more specific terms.
	kws := t.Keywords
	if len(kws) == 0 {
		return nil
	}

	// Sort by length ascending (shorter = more specific command names).
	sorted := make([]string, len(kws))
	copy(sorted, kws)
	sort.SliceStable(sorted, func(i, j int) bool {
		return len(sorted[i]) < len(sorted[j])
	})

	// Take up to 5 keywords, skipping those shorter than 3 chars.
	var selected []string
	for _, kw := range sorted {
		if len(kw) < 3 {
			continue
		}
		selected = append(selected, regexp.QuoteMeta(kw))
		if len(selected) == 5 {
			break
		}
	}
	if len(selected) == 0 {
		return nil
	}

	pattern := "(?i)(" + strings.Join(selected, "|") + ")"

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
			ID: "T0840", SubID: "T0840", Name: "Network Scanning",
			TacticIDs: []string{"TA0102"}, TacticNames: []string{"discovery"},
			URL: "https://attack.mitre.org/techniques/T0840/",
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
