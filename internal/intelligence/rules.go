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
	// Field is event_type, command, text (the lower-cased command, payload
	// and client fingerprint, as Categorize reads them), username, protocol,
	// honeypot, source_port, categories or metadata_<key>.
	Field   string
	Pattern string // regex
	Negate  bool
	// Categories, for Field "categories", lists the category IDs of which
	// the event must have one; it is looked up instead of Pattern.
	Categories []string
}

// catCond is a condition that the event has at least one of the given
// attack categories (see Categorize).
func catCond(ids ...string) Condition {
	return Condition{Field: "categories", Pattern: `(?:^|,)(?:` + strings.Join(ids, "|") + `)(?:,|$)`,
		Categories: append([]string(nil), ids...)}
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
// A category condition has a nil regexp: it is a set lookup.
type compiledRule struct {
	Rule
	compiled []*regexp.Regexp
}

// compileRules compiles a slice of Rules into compiledRules.
// Rules whose patterns fail to compile are silently dropped.
func compileRules(rules []Rule) []compiledRule {
	result := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := compiledRule{Rule: r, compiled: make([]*regexp.Regexp, len(r.Conditions))}
		ok := true
		for j, cond := range r.Conditions {
			if cond.Field == "categories" && len(cond.Categories) > 0 {
				continue
			}
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

// Tactics by their ATT&CK short name: Enterprise v18 (where Defense Evasion
// became stealth and defense-impairment) and the ICS matrix, whose
// discovery and collection carry other IDs.
var (
	enterpriseTactics = map[string]string{
		"reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001",
		"execution": "TA0002", "persistence": "TA0003", "privilege-escalation": "TA0004",
		"stealth": "TA0005", "defense-impairment": "TA0112", "credential-access": "TA0006",
		"discovery": "TA0007", "lateral-movement": "TA0008", "collection": "TA0009",
		"command-and-control": "TA0011", "exfiltration": "TA0010", "impact": "TA0040",
	}
	icsTactics = map[string]string{
		"discovery": "TA0102", "collection": "TA0100", "impair-process-control": "TA0106",
		"inhibit-response-function": "TA0107",
	}
)

// tech is an Enterprise technique under tactic, at full confidence; ics is an
// ICS one. on, conf and when finish a rule.
func tech(id, name, tactic string, priority int) Rule {
	return Rule{TechniqueID: id, Name: name, TacticName: tactic, TacticID: enterpriseTactics[tactic],
		KillChain: tacticToKillChain[tactic], Priority: priority, Confidence: 1.0}
}

func ics(id, name, tactic string, priority int) Rule {
	r := tech(id, name, tactic, priority)
	r.TacticID = icsTactics[tactic]
	return r
}

func (r Rule) on(honeypots ...string) Rule { r.Honeypots = honeypots; return r }
func (r Rule) conf(c float64) Rule         { r.Confidence = c; return r }
func (r Rule) when(conds ...Condition) Rule {
	r.Conditions = append(append([]Condition(nil), r.Conditions...), conds...)
	return r
}

// etCond matches the event type; textCond the lower-cased command and
// payload together (a web request, a Redis or SIP line, as Categorize reads
// them).
func etCond(pattern string) Condition { return Condition{Field: "event_type", Pattern: pattern} }

func textCond(res ...*regexp.Regexp) Condition {
	c := cmdCond(res...)
	c.Field = "text"
	return c
}

// catBand is the priority band of a category's rules: the more specific the
// category (categorySpecificity), the higher, so an event's technique is
// the one of its most specific category. A band is 8 wide: offset 0 is the
// category's own technique, 1-7 a sub-technique the evidence shows.
func catBand(cat string, offset int) int { return 280 - 8*categoryRankOf[cat] + offset }

// catTech is a technique for an event of category cat.
func catTech(cat string, offset int, id, name, tactic string) Rule {
	return tech(id, name, tactic, catBand(cat, offset)).when(catCond(cat))
}

// Evidence for sub-techniques, beside the category patterns themselves.
var (
	evSudo          = regexp.MustCompile(catCmdStart + `(?:sudo)` + catCmdEnd + `|/etc/sudoers\b`)
	evSUID          = regexp.MustCompile(`\bfind\b[^;&|\n]*-perm\s+[-/+]?(?:u=s|g=s|ug=s|[246]000)\b|\bchmod\s+(?:-[a-z]+\s+)*(?:[ugoa]*\+[rwx]*s[rwx]*|[2-7][0-7]{3})\b`)
	evSuLike        = regexp.MustCompile(catCmdStart + `(?:su|pkexec|doas)` + catCmdEnd)
	evRCScript      = regexp.MustCompile(catWrite + `/etc/(?:rc\.local|init\.d/|rc\d\.d/|inittab)|\bupdate-rc\.d\s|\bchkconfig\s+--add\s`)
	evPreload       = regexp.MustCompile(catWrite + `/etc/ld\.so\.preload\b`)
	evHistoryOff    = regexp.MustCompile(`\bunset\s+(?:HISTFILE|HISTSIZE|HISTFILESIZE|HISTORY|HISTSAVE)\b|\b(?:HISTSIZE|HISTFILESIZE)=0\b|\bHISTFILE=/dev/null\b|\bset\s+\+o\s+history\b`)
	evFirewall      = regexp.MustCompile(`\biptables\b|\bip6tables\b|\bufw\s+disable\b|\bfirewalld\b|\bnftables\b`)
	evSSHWipe       = regexp.MustCompile(`\brm\s+(?:-[a-z]+\s+)*(?:~/|\$home/|/root/|/home/[^/\s]+/)?\.ssh\b|\brm\s+(?:-[a-z]+\s+)*[^\s;&|]*authorized_keys\b`)
	evRivalKill     = regexp.MustCompile(`(?:\b(?:pkill|killall)\s+[^;&|\n]*|\bkill\s+-9\s+\$\(\s*(?:pgrep|pidof)\s[^)]*|\bgrep\s[^|;\n]*)(?i:` + catRivalNames + `)`)
	evSSHKeyRead    = regexp.MustCompile(`\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b|/etc/ssh/ssh_host_[a-z0-9]+_key\b|-name\s+["']?id_(?:rsa|dsa|ecdsa|ed25519)\b`)
	evHistoryRead   = regexp.MustCompile(`\.(?:bash|zsh|ash|sh|mysql|psql|python|rediscli|node_repl)_history\b`)
	evMetadata      = regexp.MustCompile(`(?:` + catMetadataIP + `)`)
	evForkBomb      = regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)
	evFloodTool     = regexp.MustCompile(`(?i)\bhping3?\b[^;&|\n]*--flood\b|\b(?:slowloris|mhddos|xerxes|ufonet|goldeneye|torshammer|synflood|udpflood|loic|hoic)\b|\b(?:hulk|ddos)\.(?:py|pl)\b`)
	evRemoteSSH     = regexp.MustCompile(catCmdStart + `(?:ssh|scp|sshpass)\s`)
	evNetScanner    = catShellCmd(`masscan|zmap|nmap|pnscan|zgrab|zgrab2`)
	evPassCracker   = catShellCmd(`hydra|medusa|ncrack|patator|crowbar`)
	evTunnelTool    = catShellCmd(`chisel|ngrok|frpc|frps|gost|v2ray`)
	evVirtCheck     = regexp.MustCompile(catCmdStart + `(?:systemd-detect-virt|virt-what|dmidecode|imvirt)` + catCmdEnd + `|/proc/(?:1|self)/cgroup\b|/sys/class/dmi/`)
	evSysInfo       = regexp.MustCompile(catCmdStart + `(?:uname|hostname|hostnamectl|nproc|free|lscpu|lspci|lsusb|lshw|lsblk|uptime|getconf|lsb_release|nvidia-smi|df)` + catCmdEnd + `|/proc/(?:cpuinfo|meminfo|version|mounts|uptime|stat\b)|/etc/(?:os-release|issue|lsb-release|redhat-release|debian_version|hostname|machine-id)|/proc/self/(?:exe|maps|cmdline)\b`)
	evUserInfo      = regexp.MustCompile(catCmdStart + `(?:whoami|id|w|who|last|lastlog)` + catCmdEnd)
	evAccounts      = regexp.MustCompile(`/etc/(?:passwd|group)\b`)
	evNetConfig     = regexp.MustCompile(catCmdStart + `(?:ifconfig|route)` + catCmdEnd + `|` + catCmdStart + `ip\s+(?:-[a-z0-9]+\s+)*(?:a|addr|address|r|route|l|link)\b|/etc/(?:hosts|resolv\.conf)\b|/sys/class/net/`)
	evNetConns      = regexp.MustCompile(catCmdStart + `(?:netstat|ss)` + catCmdEnd + `|/proc/net/`)
	evNeighbours    = regexp.MustCompile(catCmdStart + `(?:arp)` + catCmdEnd + `|` + catCmdStart + `ip\s+(?:-[a-z0-9]+\s+)*(?:n|neigh|neighbor)\b`)
	evSoftware      = regexp.MustCompile(catCmdStart + `(?:which)` + catCmdEnd)
	evListing       = regexp.MustCompile(catCmdStart + `(?:ls|dir)` + catCmdEnd)
	evVulnScanner   = regexp.MustCompile(`\b(?:nuclei|nikto|sqlmap|wpscan|acunetix|qualys|openvas|nessus|whatweb|projectdiscovery|interactsh|oast\.(?:pro|live|site|online|fun|me))\b`)
	evDirBuster     = regexp.MustCompile(`\b(?:dirbuster|gobuster|ffuf|feroxbuster|dirb)\b`)
	evDownload      = regexp.MustCompile(`\b(?:` + catDownloaders + `)\b|/dev/tcp/`)
	evRedisKeysFile = regexp.MustCompile(`dbfilename\s+["']?authorized_keys`)
	evXPCmdShell    = regexp.MustCompile(`xp_cmdshell`)
	evPrivEscEnum   = regexp.MustCompile(`(?i)\b(?:linpeas|linenum|linux-exploit-suggester|unix-privesc-check|suid3num|lse)(?:\.sh)?\b|\bles\.sh\b|\bgetcap\s+-r\b`)
)

// Event types shared by the rules. The collector keeps each honeypot's own
// dotted event names (cowrie.login.failed, heralding.login.failed,
// conpot.modbus.read, …), so the rules match those as well as the bare
// legacy names.
const (
	loginSuccessPattern       = `(?:login|auth)[._]success`
	refrigerationWritePattern = `^refrigeration\.write\.(?:attempt|success|denied)$`
	commandEventPattern       = `(?:^|[._])(?:command|input)(?:[._]|$)`
)

// DefaultRules returns the built-in classification ruleset, highest
// priority first. Every attack category has its own ATT&CK technique, so the
// technique shown beside a category always agrees with it; within a
// category a sub-technique is chosen by the same evidence the category was
// found by. Techniques are ATT&CK v18 (Enterprise) and the current ICS
// matrix: a revoked ID such as T0855 or T1562.001 is never assigned.
func DefaultRules() []Rule {
	rules := []Rule{
		// ---------------------------------------------------------------
		// Industrial devices: the protocol operation names the technique.
		// An event shows an attempt; it never proves a physical effect.
		// ---------------------------------------------------------------
		// The refrigeration supervisor's write actions: acknowledging alarms
		// silences them, defrost and the main switch are commands, and
		// write_val changes a setpoint.
		ics("T0878", "Alarm Suppression", "inhibit-response-function", 322).on("refrigeration").conf(0.6).
			when(etCond(refrigerationWritePattern), Condition{Field: "metadata_action", Pattern: `^write_alarm_ack$`}),
		ics("T1692.001", "Command Message", "impair-process-control", 321).on("refrigeration").conf(0.6).
			when(etCond(refrigerationWritePattern), Condition{Field: "metadata_action", Pattern: `^(?:set_defrost|set_main_switch)$`}),
		ics("T0836", "Modify Parameter", "impair-process-control", 320).on("refrigeration").conf(0.6).
			when(etCond(refrigerationWritePattern)),
		// Modbus Report Server ID (17) and Read Device Identification (43)
		// ask what the device is.
		ics("T0888", "Remote System Information Discovery", "discovery", 315).on("conpot").conf(0.7).
			when(etCond(`^conpot\.modbus\.read$`), Condition{Field: "metadata_function_code", Pattern: `^(?:17|43)$`}),
		ics("T1692.001", "Command Message", "impair-process-control", 310).on("conpot").conf(0.8).
			when(etCond(`^(?:command|conpot\.[a-z0-9_]+\.command)$`)),
		// A read of coils or registers reads the process state; it names no
		// point or tag and proves no scan.
		ics("T0801", "Monitor Process State", "collection", 305).on("conpot").conf(0.6).
			when(etCond(`^conpot\.[a-z0-9_]+\.read$`)),
		ics("T0888", "Remote System Information Discovery", "discovery", 300).on("conpot").conf(0.6).
			when(etCond(`^conpot\.[a-z0-9_]+\.request$`)),
		ics("T0846", "Remote System Discovery", "discovery", 295).on("conpot").conf(0.5).
			when(etCond(`^(?:probe|conpot\.[a-z0-9_]+\.probe)$`)),

		// A login the honeypot accepted: the guess gave the attacker a
		// working account. The refrigeration supervisor's logins stay
		// observations (a reused export credential trips its canary).
		tech("T1078", "Valid Accounts", "initial-access", 290).conf(0.8).
			when(etCond(loginSuccessPattern), Condition{Field: "honeypot", Pattern: `^refrigeration$`, Negate: true}),

		// ---------------------------------------------------------------
		// One technique per category, most specific category first.
		// ---------------------------------------------------------------
		ics("T0888", "Remote System Information Discovery", "discovery", catBand(CatICSAttack, 0)).conf(0.5).when(catCond(CatICSAttack)),
		catTech(CatAmplification, 0, "T1498.002", "Reflection Amplification", "impact"),

		catTech(CatVoIPFraud, 2, "T1110", "Brute Force", "credential-access").conf(0.6).when(etCond(`register`)),
		catTech(CatVoIPFraud, 1, "T1496", "Resource Hijacking", "impact").conf(0.6).when(etCond(`invite`)),
		catTech(CatVoIPFraud, 0, "T1595", "Active Scanning", "reconnaissance").conf(0.8),

		// Redis writing its dump as a cron table or authorized_keys is the
		// persistence it is abused for.
		catTech(CatDatabaseAbuse, 4, "T1053.003", "Cron", "persistence").when(textCond(catRedisCron)),
		catTech(CatDatabaseAbuse, 3, "T1098.004", "SSH Authorized Keys", "persistence").when(textCond(catRedisSSHKeyData, evRedisKeysFile)),
		catTech(CatDatabaseAbuse, 2, "T1485", "Data Destruction", "impact").when(textCond(catRedisFlush)),
		catTech(CatDatabaseAbuse, 1, "T1505.001", "SQL Stored Procedures", "persistence").when(textCond(evXPCmdShell)),
		catTech(CatDatabaseAbuse, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),

		catTech(CatExploitAttempt, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),
		catTech(CatWebShell, 0, "T1505.003", "Web Shell", "persistence"),
		catTech(CatCryptomining, 0, "T1496.001", "Compute Hijacking", "impact"),
		// A loader fetches the bot; a bare busybox probe only checks for one.
		catTech(CatBotnet, 1, "T1105", "Ingress Tool Transfer", "command-and-control").when(textCond(evDownload)),
		catTech(CatBotnet, 0, "T1584.005", "Botnet", "resource-development").conf(0.8),

		catTech(CatCodeInjection, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),
		catTech(CatCommandInjection, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),
		catTech(CatSQLInjection, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),
		catTech(CatXSS, 0, "T1190", "Exploit Public-Facing Application", "initial-access").conf(0.8),
		catTech(CatSSRF, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),
		catTech(CatFileInclusion, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),
		catTech(CatPathTraversal, 0, "T1190", "Exploit Public-Facing Application", "initial-access"),
		// Hunting for .env, .git or a config backup is a wordlist scan.
		catTech(CatConfigExposure, 0, "T1595.003", "Wordlist Scanning", "reconnaissance"),
		catTech(CatFileUpload, 0, "T1105", "Ingress Tool Transfer", "command-and-control"),

		catTech(CatCredentialAccess, 4, "T1003.008", "/etc/passwd and /etc/shadow", "credential-access").when(cmdCond(catCredShadow)),
		catTech(CatCredentialAccess, 3, "T1552.004", "Private Keys", "credential-access").when(cmdCond(evSSHKeyRead)),
		catTech(CatCredentialAccess, 2, "T1552.005", "Cloud Instance Metadata API", "credential-access").when(textCond(evMetadata)),
		catTech(CatCredentialAccess, 1, "T1552.003", "Shell History", "credential-access").when(cmdCond(evHistoryRead)),
		catTech(CatCredentialAccess, 0, "T1552.001", "Credentials In Files", "credential-access"),

		catTech(CatPrivilegeEscalation, 4, "T1548.003", "Sudo and Sudo Caching", "privilege-escalation").when(cmdCond(evSudo)),
		catTech(CatPrivilegeEscalation, 3, "T1548.001", "Setuid and Setgid", "privilege-escalation").when(cmdCond(evSUID)),
		catTech(CatPrivilegeEscalation, 2, "T1548", "Abuse Elevation Control Mechanism", "privilege-escalation").when(cmdCond(evSuLike)),
		// linpeas and its kin only look for a way up.
		catTech(CatPrivilegeEscalation, 1, "T1082", "System Information Discovery", "discovery").conf(0.8).when(cmdCond(evPrivEscEnum)),
		// Kernel and polkit exploits and exploit builds.
		catTech(CatPrivilegeEscalation, 0, "T1068", "Exploitation for Privilege Escalation", "privilege-escalation").conf(0.8),

		catTech(CatPersistence, 7, "T1098.004", "SSH Authorized Keys", "persistence").when(cmdCond(catPersistKeys, catPersistSSHD)),
		catTech(CatPersistence, 7, "T1098.004", "SSH Authorized Keys", "persistence").when(textCond(catRedisSSHKeyData, evRedisKeysFile)),
		catTech(CatPersistence, 6, "T1053.003", "Cron", "persistence").when(cmdCond(catPersistCron, catRedisCron)),
		catTech(CatPersistence, 6, "T1053.003", "Cron", "persistence").when(textCond(catRedisCron)),
		catTech(CatPersistence, 5, "T1574.006", "Dynamic Linker Hijacking", "persistence").when(cmdCond(evPreload)),
		catTech(CatPersistence, 4, "T1037.004", "RC Scripts", "persistence").when(cmdCond(evRCScript)),
		catTech(CatPersistence, 3, "T1543.002", "Systemd Service", "persistence").when(cmdCond(catPersistService)),
		catTech(CatPersistence, 2, "T1136.001", "Local Account", "persistence").when(cmdCond(catPersistAccount)),
		catTech(CatPersistence, 1, "T1546.004", "Unix Shell Configuration Modification", "persistence").when(cmdCond(catPersistProfile)),
		// A password change or another account change.
		catTech(CatPersistence, 0, "T1098", "Account Manipulation", "persistence").conf(0.8),

		catTech(CatDefenseEvasion, 6, "T1690", "Prevent Command History Logging", "defense-impairment").when(cmdCond(evHistoryOff)),
		catTech(CatDefenseEvasion, 5, "T1070.003", "Clear Command History", "stealth").when(cmdCond(catEvadeHistory)),
		catTech(CatDefenseEvasion, 4, "T1685.006", "Clear Linux or Mac System Logs", "defense-impairment").when(cmdCond(catEvadeLogs)),
		// Removing .ssh locks the owner and rival bots out of the account.
		catTech(CatDefenseEvasion, 3, "T1531", "Account Access Removal", "impact").when(cmdCond(evSSHWipe)),
		catTech(CatDefenseEvasion, 2, "T1686", "Disable or Modify System Firewall", "defense-impairment").when(cmdCond(evFirewall)),
		// Killing a rival's miner or bot stops its service.
		catTech(CatDefenseEvasion, 1, "T1489", "Service Stop", "impact").conf(0.8).when(cmdCond(evRivalKill)),
		catTech(CatDefenseEvasion, 0, "T1685", "Disable or Modify Tools", "defense-impairment"),

		catTech(CatImpact, 2, "T1499.001", "OS Exhaustion Flood", "impact").when(cmdCond(evForkBomb)),
		catTech(CatImpact, 1, "T1498", "Network Denial of Service", "impact").when(cmdCond(evFloodTool)),
		// Wiping disks or data, and the ransom notes left after deleting it.
		catTech(CatImpact, 0, "T1485", "Data Destruction", "impact"),

		// ssh -L/-R/-D to another host tunnels through it.
		catTech(CatLateralMovement, 4, "T1572", "Protocol Tunneling", "command-and-control").when(cmdCond(catSSHForward)),
		catTech(CatLateralMovement, 3, "T1046", "Network Service Discovery", "discovery").when(cmdCond(evNetScanner)),
		catTech(CatLateralMovement, 2, "T1110", "Brute Force", "credential-access").when(cmdCond(evPassCracker)),
		catTech(CatLateralMovement, 1, "T1021.004", "SSH", "lateral-movement").when(cmdCond(evRemoteSSH)),
		catTech(CatLateralMovement, 0, "T1021", "Remote Services", "lateral-movement").conf(0.8),

		// Forwarding typed in a shell or a tunnelling tool; a forward the
		// SSH client asks for, an open-proxy check or an SMTP relay uses the
		// honeypot as a proxy.
		catTech(CatProxyAbuse, 1, "T1572", "Protocol Tunneling", "command-and-control").when(cmdCond(catSSHForward, evTunnelTool)),
		catTech(CatProxyAbuse, 0, "T1090", "Proxy", "command-and-control"),

		catTech(CatMalwareDownload, 0, "T1105", "Ingress Tool Transfer", "command-and-control"),

		// Reconnaissance after login. A VM or container check is the
		// attacker looking for a sandbox (or a honeypot).
		catTech(CatRecon, 7, "T1497.001", "System Checks", "stealth").when(cmdCond(evVirtCheck)),
		catTech(CatRecon, 6, "T1082", "System Information Discovery", "discovery").when(cmdCond(evSysInfo)),
		catTech(CatRecon, 5, "T1033", "System Owner/User Discovery", "discovery").when(cmdCond(evUserInfo)),
		catTech(CatRecon, 4, "T1087.001", "Local Account", "discovery").when(cmdCond(evAccounts)),
		catTech(CatRecon, 3, "T1016", "System Network Configuration Discovery", "discovery").when(cmdCond(evNetConfig, catIPLookup)),
		catTech(CatRecon, 2, "T1049", "System Network Connections Discovery", "discovery").when(cmdCond(evNetConns)),
		catTech(CatRecon, 2, "T1018", "Remote System Discovery", "discovery").when(cmdCond(evNeighbours)),
		catTech(CatRecon, 1, "T1518", "Software Discovery", "discovery").when(cmdCond(evSoftware)),
		catTech(CatRecon, 1, "T1083", "File and Directory Discovery", "discovery").when(cmdCond(evListing)),
		catTech(CatRecon, 0, "T1082", "System Information Discovery", "discovery").conf(0.8),

		catTech(CatBruteForce, 0, "T1110", "Brute Force", "credential-access"),

		catTech(CatScanning, 3, "T1595.003", "Wordlist Scanning", "reconnaissance").when(textCond(evDirBuster)),
		catTech(CatScanning, 2, "T1595.002", "Vulnerability Scanning", "reconnaissance").when(textCond(evVulnScanner)),
		// A bare connection is one knock: scanning, but on thin evidence.
		catTech(CatScanning, 1, "T1595", "Active Scanning", "reconnaissance").conf(0.5).when(etCond(catConnectEvent.String())),
		catTech(CatScanning, 0, "T1595", "Active Scanning", "reconnaissance").conf(0.8),

		// ---------------------------------------------------------------
		// A shell command no category names is still execution in a shell.
		// It ranks above the rules generated from ATT&CK's text (priority
		// 10), whose code terms label everyday commands (systemctl status)
		// too loosely; on adbhoney those rules still name a command.
		// ---------------------------------------------------------------
		tech("T1059.004", "Unix Shell", "execution", 20).on("cowrie", "ssh-proxy").conf(0.5).
			when(etCond(commandEventPattern), Condition{Field: "command", Pattern: `\S`}),
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	return rules
}
