package intelligence

import (
	"regexp"
	"sort"
	"strings"
)

// Rule maps event patterns to an ATT&CK technique.
type Rule struct {
	TechniqueID string
	TacticID    string
	TacticName  string
	Name        string
	// KillChain is one of: reconnaissance|initial-access|execution|discovery|
	// persistence|privilege-escalation|collection|c2|exfiltration
	KillChain  string
	Honeypots  []string // empty = applies to all honeypots
	Conditions []Condition
	Priority   int     // higher = evaluated first
	Confidence float64 // 0.0–1.0; static rules default to 1.0
}

// MergeRules combines static and dynamic rules.
// Dynamic rules whose TechniqueID is already covered by a static rule are
// dropped. The returned slice is sorted by Priority descending.
func MergeRules(static []Rule, dynamic []Rule) []Rule {
	// Build a set of technique IDs already covered by static rules.
	covered := make(map[string]bool, len(static))
	for _, r := range static {
		covered[r.TechniqueID] = true
	}

	merged := make([]Rule, len(static))
	copy(merged, static)

	for _, dr := range dynamic {
		if covered[dr.TechniqueID] {
			continue
		}
		merged = append(merged, dr)
		covered[dr.TechniqueID] = true
	}

	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Priority > merged[j].Priority
	})

	return merged
}

// Condition is a single match condition on an event field.
type Condition struct {
	Field   string // event_type|command|username|protocol|honeypot|source_port|categories
	Pattern string // regex
	Negate  bool
}

// catCond is a condition that the event has at least one of the given
// attack categories (see Categorize).
func catCond(ids ...string) Condition {
	return Condition{Field: "categories", Pattern: `(?:^|,)(?:` + strings.Join(ids, "|") + `)(?:,|$)`}
}

// cmdCond is a command condition made of category patterns, so a rule
// picks its technique with the same pattern the category was found by.
func cmdCond(res ...*regexp.Regexp) Condition {
	parts := make([]string, len(res))
	for i, re := range res {
		parts[i] = `(?:` + re.String() + `)`
	}
	return Condition{Field: "command", Pattern: strings.Join(parts, "|")}
}

// compiledRule is a Rule with pre-compiled regexps for efficient matching.
type compiledRule struct {
	Rule
	compiled []*regexp.Regexp
}

// defaultCompiledRules holds the singleton compiled ruleset of static rules only.
var defaultCompiledRules []compiledRule

func init() {
	raw := DefaultRules()
	defaultCompiledRules = make([]compiledRule, len(raw))
	for i, r := range raw {
		cr := compiledRule{Rule: r, compiled: make([]*regexp.Regexp, len(r.Conditions))}
		for j, cond := range r.Conditions {
			cr.compiled[j] = regexp.MustCompile(cond.Pattern)
		}
		defaultCompiledRules[i] = cr
	}
}

// compileRules compiles a slice of Rules into compiledRules.
// Rules whose patterns fail to compile are silently dropped.
func compileRules(rules []Rule) []compiledRule {
	result := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := compiledRule{Rule: r, compiled: make([]*regexp.Regexp, len(r.Conditions))}
		ok := true
		for j, cond := range r.Conditions {
			rx, err := regexp.Compile(cond.Pattern)
			if err != nil {
				ok = false
				break
			}
			cr.compiled[j] = rx
		}
		if ok {
			result = append(result, cr)
		}
	}
	return result
}

// DefaultRules returns the built-in classification ruleset.
// Rules are returned in priority order (highest first).
// Event-type patterns shared by the default rules. The collector keeps each
// honeypot's own dotted event names (cowrie.login.failed, heralding.login.failed,
// dionaea.connection.accept, conpot.modbus.new_connection, endlessh.connection.accept,
// …), so the rules match those as well as the bare legacy names.
const (
	loginFailedPattern = `login[._]failed`
	connectionPattern  = `^(connection|probe)$|session\.connect$|connection\.accept$|new_connection$|\.probe$`
)

func DefaultRules() []Rule {
	return []Rule{
		// -----------------------------------------------------------------------
		// T0855 Unauthorized Command (ICS) — priority 200
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T0855",
			TacticID:    "TA0104",
			TacticName:  "impair-process-control",
			Name:        "ICS Unauthorized Command",
			KillChain:   "initial-access",
			Honeypots:   []string{"conpot"},
			Priority:    200,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: `command`},
			},
		},

		// -----------------------------------------------------------------------
		// T0840 ICS Network Scanning — priority 190
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T0840",
			TacticID:    "TA0102",
			TacticName:  "discovery",
			Name:        "ICS Network Scanning",
			KillChain:   "reconnaissance",
			Honeypots:   []string{"conpot"},
			Priority:    190,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: connectionPattern},
			},
		},

		// -----------------------------------------------------------------------
		// T1190 Exploit Public-Facing Application — priority 180
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1190",
			TacticID:    "TA0001",
			TacticName:  "initial-access",
			Name:        "Exploit Public-Facing Application",
			KillChain:   "initial-access",
			Honeypots:   []string{"tanner", "honeyaml", "elasticpot", "ciscoasa", "citrixhoneypot"},
			Priority:    180,
			Confidence:  1.0,
			Conditions:  []Condition{},
		},

		// -----------------------------------------------------------------------
		// T1190 Exploit Public-Facing Application, on any honeypot, for an
		// event whose category is an attack on the service — priority 179
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1190",
			TacticID:    "TA0001",
			TacticName:  "initial-access",
			Name:        "Exploit Public-Facing Application",
			KillChain:   "initial-access",
			Honeypots:   []string{},
			Priority:    179,
			Confidence:  1.0,
			Conditions: []Condition{catCond(CatExploitAttempt, CatSQLInjection, CatXSS, CatCommandInjection,
				CatCodeInjection, CatPathTraversal, CatFileInclusion, CatSSRF, CatWebShell)},
		},

		// -----------------------------------------------------------------------
		// T1110.004 Credential Stuffing (heralding) — priority 170
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1110.004",
			TacticID:    "TA0006",
			TacticName:  "credential-access",
			Name:        "Credential Stuffing",
			KillChain:   "initial-access",
			Honeypots:   []string{"heralding"},
			Priority:    170,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: loginFailedPattern},
			},
		},

		// -----------------------------------------------------------------------
		// T1110.003 Password Spraying — priority 160
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1110.003",
			TacticID:    "TA0006",
			TacticName:  "credential-access",
			Name:        "Password Spraying",
			KillChain:   "initial-access",
			Honeypots:   []string{},
			Priority:    160,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: loginFailedPattern},
				// metadata field "unique_usernames" present signals spraying
				{Field: "metadata_unique_usernames", Pattern: `.+`},
			},
		},

		// -----------------------------------------------------------------------
		// T1110.001 Password Guessing — priority 150
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1110.001",
			TacticID:    "TA0006",
			TacticName:  "credential-access",
			Name:        "Password Guessing",
			KillChain:   "initial-access",
			Honeypots:   []string{},
			Priority:    150,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: loginFailedPattern},
				// metadata field "attempt_count" present signals repeated attempts
				{Field: "metadata_attempt_count", Pattern: `.+`},
			},
		},

		// -----------------------------------------------------------------------
		// T1110 Brute Force (cowrie / heralding) — priority 140
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1110",
			TacticID:    "TA0006",
			TacticName:  "credential-access",
			Name:        "Brute Force",
			KillChain:   "initial-access",
			Honeypots:   []string{"cowrie", "heralding"},
			Priority:    140,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: loginFailedPattern},
			},
		},

		// -----------------------------------------------------------------------
		// T1548 Abuse Elevation Control Mechanism: sudo, su, pkexec, SUID —
		// priority 130. A plain chmod 777 or chmod +x is not escalation.
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1548",
			TacticID:    "TA0004",
			TacticName:  "privilege-escalation",
			Name:        "Abuse Elevation Control Mechanism",
			KillChain:   "privilege-escalation",
			Honeypots:   []string{},
			Priority:    130,
			Confidence:  1.0,
			Conditions: []Condition{
				catCond(CatPrivilegeEscalation),
				{Field: "command", Pattern: `\b(?:sudo|su|pkexec|doas|chmod)\b|-perm\b`},
			},
		},

		// -----------------------------------------------------------------------
		// T1053 Scheduled Task/Job: writing a cron job, in a shell or through
		// Redis — priority 120. Listing one (crontab -l) is discovery, and
		// systemctl enable or an init script is not a scheduled task.
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1053",
			TacticID:    "TA0003",
			TacticName:  "persistence",
			Name:        "Scheduled Task/Job",
			KillChain:   "persistence",
			Honeypots:   []string{},
			Priority:    120,
			Confidence:  1.0,
			Conditions:  []Condition{catCond(CatPersistence), cmdCond(catPersistCron, catRedisCron)},
		},

		// -----------------------------------------------------------------------
		// T1105 Ingress Tool Transfer: a download or an upload, as the
		// categories found it (an IDS signature naming wget is not one) —
		// priority 110
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1105",
			TacticID:    "TA0011",
			TacticName:  "command-and-control",
			Name:        "Ingress Tool Transfer",
			KillChain:   "c2",
			Honeypots:   []string{},
			Priority:    110,
			Confidence:  1.0,
			Conditions:  []Condition{catCond(CatMalwareDownload, CatFileUpload, CatBotnet)},
		},

		// -----------------------------------------------------------------------
		// T1049 Network Connections Discovery — priority 100
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1049",
			TacticID:    "TA0007",
			TacticName:  "discovery",
			Name:        "System Network Connections Discovery",
			KillChain:   "discovery",
			Honeypots:   []string{},
			Priority:    100,
			Confidence:  1.0,
			Conditions: []Condition{
				catCond(CatRecon),
				{Field: "command", Pattern: `netstat|ss\s+-|/proc/net`},
			},
		},

		// -----------------------------------------------------------------------
		// T1016 Network Config Discovery — priority 90
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1016",
			TacticID:    "TA0007",
			TacticName:  "discovery",
			Name:        "System Network Configuration Discovery",
			KillChain:   "discovery",
			Honeypots:   []string{},
			Priority:    90,
			Confidence:  1.0,
			Conditions: []Condition{
				catCond(CatRecon),
				{Field: "command", Pattern: `ifconfig|ip\s+(addr|route|link)|netstat\s+-i|route\s+-n`},
			},
		},

		// -----------------------------------------------------------------------
		// T1033 System Owner/User Discovery — priority 80
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1033",
			TacticID:    "TA0007",
			TacticName:  "discovery",
			Name:        "System Owner/User Discovery",
			KillChain:   "discovery",
			Honeypots:   []string{},
			Priority:    80,
			Confidence:  1.0,
			Conditions: []Condition{
				catCond(CatRecon),
				{Field: "command", Pattern: `\bwhoami\b|\bid\b|\bw\b|\bwho\b|\blast\b`},
			},
		},

		// -----------------------------------------------------------------------
		// T1082 System Information Discovery — priority 70
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1082",
			TacticID:    "TA0007",
			TacticName:  "discovery",
			Name:        "System Information Discovery",
			KillChain:   "discovery",
			Honeypots:   []string{},
			Priority:    70,
			Confidence:  1.0,
			Conditions: []Condition{
				catCond(CatRecon),
				{Field: "command", Pattern: `uname|/proc/version|/etc/os-release|lsb_release|hostnamectl`},
			},
		},

		// -----------------------------------------------------------------------
		// T1059.004 Unix Shell — priority 60
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1059.004",
			TacticID:    "TA0002",
			TacticName:  "execution",
			Name:        "Unix Shell",
			KillChain:   "execution",
			Honeypots:   []string{"cowrie"},
			Priority:    60,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: `command`},
				{Field: "command", Pattern: `.+`},
			},
		},

		// -----------------------------------------------------------------------
		// T1046 Network Service Discovery — priority 50
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1046",
			TacticID:    "TA0007",
			TacticName:  "discovery",
			Name:        "Network Service Discovery",
			KillChain:   "reconnaissance",
			Honeypots:   []string{},
			Priority:    50,
			Confidence:  1.0,
			Conditions: []Condition{
				{Field: "event_type", Pattern: connectionPattern},
				// username must be absent (no auth attempted)
				{Field: "username", Pattern: `.+`, Negate: true},
			},
		},
	}
}
