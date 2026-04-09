package intelligence

import "regexp"

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
	Priority   int // higher = evaluated first
}

// Condition is a single match condition on an event field.
type Condition struct {
	Field   string // event_type|command|username|protocol|honeypot|source_port
	Pattern string // regex
	Negate  bool
}

// compiledRule is a Rule with pre-compiled regexps for efficient matching.
type compiledRule struct {
	Rule
	compiled []*regexp.Regexp
}

// defaultCompiledRules holds the singleton compiled ruleset.
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

// DefaultRules returns the built-in classification ruleset.
// Rules are returned in priority order (highest first).
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
			Conditions: []Condition{
				{Field: "event_type", Pattern: `connection|probe`},
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
			Conditions:  []Condition{},
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
			Conditions: []Condition{
				{Field: "event_type", Pattern: `login_failed`},
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
			Conditions: []Condition{
				{Field: "event_type", Pattern: `login_failed`},
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
			Conditions: []Condition{
				{Field: "event_type", Pattern: `login_failed`},
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
			Conditions: []Condition{
				{Field: "event_type", Pattern: `login_failed`},
			},
		},

		// -----------------------------------------------------------------------
		// T1548 Privilege Escalation — priority 130
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1548",
			TacticID:    "TA0004",
			TacticName:  "privilege-escalation",
			Name:        "Abuse Elevation Control Mechanism",
			KillChain:   "privilege-escalation",
			Honeypots:   []string{},
			Priority:    130,
			Conditions: []Condition{
				{Field: "command", Pattern: `sudo\s|su\s+root|\bchmod\s+[0-7]*7[0-7][0-7]|chown\s+root|pkexec`},
			},
		},

		// -----------------------------------------------------------------------
		// T1053 Scheduled Task / Persistence — priority 120
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1053",
			TacticID:    "TA0003",
			TacticName:  "persistence",
			Name:        "Scheduled Task/Job",
			KillChain:   "persistence",
			Honeypots:   []string{},
			Priority:    120,
			Conditions: []Condition{
				{Field: "command", Pattern: `crontab|/etc/cron|systemctl\s+enable|rc\.local|/etc/init\.d`},
			},
		},

		// -----------------------------------------------------------------------
		// T1105 Ingress Tool Transfer — priority 110
		// -----------------------------------------------------------------------
		{
			TechniqueID: "T1105",
			TacticID:    "TA0011",
			TacticName:  "command-and-control",
			Name:        "Ingress Tool Transfer",
			KillChain:   "c2",
			Honeypots:   []string{},
			Priority:    110,
			Conditions: []Condition{
				{Field: "command", Pattern: `wget|curl|fetch|tftp|ftp\s|scp\s|nc\s.*<`},
			},
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
			Conditions: []Condition{
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
			Conditions: []Condition{
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
			Conditions: []Condition{
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
			Conditions: []Condition{
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
			Conditions: []Condition{
				{Field: "event_type", Pattern: `connection|probe`},
				// username must be absent (no auth attempted)
				{Field: "username", Pattern: `.+`, Negate: true},
			},
		},
	}
}
