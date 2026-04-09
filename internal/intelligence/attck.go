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
	"strings"
	"time"
)

// attckURL is the MITRE ATT&CK enterprise STIX bundle.
const attckURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

// attckCacheFile is the name of the locally cached STIX bundle.
const attckCacheFile = "attck-enterprise.json"

// Technique represents a MITRE ATT&CK technique.
type Technique struct {
	ID          string
	SubID       string // e.g. "T1110.001"
	Name        string
	TacticIDs   []string
	TacticNames []string
	Description string
	URL         string
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

		tech := &Technique{
			ID:          techID,
			SubID:       techID,
			Name:        obj.Name,
			TacticNames: tacticNames,
			Description: truncate(obj.Description, 512),
			URL:         techURL,
		}

		a.techniques[techID] = tech
		count++
	}

	if count == 0 {
		return fmt.Errorf("no attack-pattern objects found in bundle")
	}
	return nil
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
