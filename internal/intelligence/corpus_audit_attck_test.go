package intelligence

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// auditTechnique is one attack-pattern of the synthetic STIX bundle below.
type auditTechnique struct {
	id, name, desc string
	tactics        []string
	platforms      []string
	deprecated     bool
}

// auditBundle builds a small STIX bundle in the shape of ATT&CK v18: the
// detection and data-source fields are gone, code terms sit in backticks in
// the description, and some techniques are deprecated rather than revoked.
// The descriptions are short paraphrases that cite the same code terms the
// real techniques do.
func auditBundle(t *testing.T) []byte {
	t.Helper()
	tactics := map[string]string{
		"persistence": "TA0003", "stealth": "TA0005", "discovery": "TA0007",
		"credential-access": "TA0006", "defense-impairment": "TA0112", "execution": "TA0002",
		"command-and-control": "TA0011", "privilege-escalation": "TA0004",
	}
	linux := []string{"Linux", "macOS", "Windows"}
	techs := []auditTechnique{
		{"T1136.001", "Local Account", "Adversaries may create a local account with the `useradd` command, or in a cluster with `kubectl`.", []string{"persistence"}, linux, false},
		{"T1059.013", "Container CLI/API", "Adversaries may run `docker ps`, `kubectl` or `curl` against a container API.", []string{"execution"}, []string{"Containers"}, false},
		{"T1105", "Ingress Tool Transfer", "Tools such as `curl`, `wget` and `scp` copy files in.", []string{"command-and-control"}, linux, false},
		{"T1564.011", "Ignore Process Interrupts", "Adversaries may run a payload under `nohup` so it survives a hang-up.", []string{"stealth"}, linux, false},
		{"T1543.002", "Systemd Service", "A unit file in `/etc/systemd/system` names its program in `ExecStart`; it is a `.service` file managed with `systemctl`.", []string{"persistence"}, []string{"Linux"}, false},
		{"T1569.003", "Systemctl", "Adversaries may run `systemctl start` on a unit; `systemctl` also lists units.", []string{"execution"}, []string{"Linux"}, false},
		{"T1690", "Prevent Command History Logging", "Setting `HISTFILE`, running `unset HISTFILE` or `export HISTFILESIZE=0` keeps `~/.bash_history` empty.", []string{"defense-impairment"}, linux, false},
		{"T1552.003", "Shell History", "Adversaries may read `~/.bash_history` or run `Get-History`.", []string{"credential-access"}, linux, false},
		{"T1036.011", "Overwrite Process Arguments", "A process may overwrite `argv[0]` so `ps` shows `cat /etc/passwd` instead; see `/proc/<PID>/cmdline`.", []string{"stealth"}, []string{"Linux"}, false},
		{"T1574.006", "Dynamic Linker Hijacking", "`LD_PRELOAD` libraries can hook `sshd`; tools like `ldd`, `iptables` or `dmesg` then load them.", []string{"persistence"}, []string{"Linux", "macOS"}, false},
		{"T1056.004", "Credential API Hooking", "Hooks may be set through `LD_PRELOAD`.", []string{"credential-access"}, linux, false},
		{"T1678", "Delay Execution", "Adversaries may delay with `sleep` or `ping`.", []string{"stealth"}, linux, false},
		{"T1685.006", "Clear Linux or Mac System Logs", "Adversaries may clear `/var/log/` files such as `/var/log/kern.log`.", []string{"defense-impairment"}, []string{"Linux", "macOS"}, false},
		{"T1003.007", "Proc Filesystem", "Credentials may be read from `/proc` and `/proc/<PID>/maps`.", []string{"credential-access"}, []string{"Linux"}, false},
		{"T1027.011", "Fileless Storage", "Payloads may be kept in `/dev/shm` or `/tmp`.", []string{"stealth"}, []string{"Linux", "Windows"}, false},
		{"T1036.008", "Masquerade File Type", "A payload may be named with a `.txt` or `.jpg` extension.", []string{"stealth"}, linux, false},
		{"T1098.004", "SSH Authorized Keys", "Adversaries may set `PermitRootLogin` to `yes` or edit `/etc/ssh/keys-<username>/authorized_keys`.", []string{"persistence"}, []string{"Linux", "macOS"}, false},
		{"T1010", "Application Window Discovery", "Adversaries may list open application windows.", []string{"discovery"}, linux, false},
		{"T1078", "Valid Accounts", "Adversaries may use valid accounts.", []string{"persistence"}, linux, false},
		{"T1078.003", "Local Accounts", "Adversaries may use local accounts.", []string{"persistence"}, linux, false},
		{"T1037.002", "Login Hook", "A login hook runs at login.", []string{"persistence"}, []string{"macOS"}, false},
		{"T1505", "Server Software Component", "Adversaries may abuse server software components.", []string{"persistence"}, linux, false},
		{"T1222.002", "Linux and Mac File and Directory Permissions Modification", "Permissions may be changed.", []string{"stealth"}, []string{"Linux", "macOS"}, false},
		{"T1153", "Source", "The `source` builtin runs a script in the current shell.", []string{"execution"}, []string{"Linux", "macOS"}, true},
	}
	objs := []map[string]any{}
	for short, id := range tactics {
		objs = append(objs, map[string]any{
			"type": "x-mitre-tactic", "name": short, "x_mitre_shortname": short,
			"external_references": []map[string]string{{"source_name": "mitre-attack", "external_id": id}},
		})
	}
	for _, tc := range techs {
		var phases []map[string]string
		for _, p := range tc.tactics {
			phases = append(phases, map[string]string{"kill_chain_name": "mitre-attack", "phase_name": p})
		}
		objs = append(objs, map[string]any{
			"type": "attack-pattern", "name": tc.name, "description": tc.desc,
			"x_mitre_platforms": tc.platforms, "x_mitre_deprecated": tc.deprecated,
			"x_mitre_is_subtechnique": strings.Contains(tc.id, "."),
			"kill_chain_phases":       phases,
			"external_references": []map[string]string{{
				"source_name": "mitre-attack", "external_id": tc.id,
				"url": "https://attack.mitre.org/techniques/" + strings.ReplaceAll(tc.id, ".", "/") + "/",
			}},
		})
	}
	b, err := json.Marshal(map[string]any{"type": "bundle", "objects": objs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// auditClassifier is a classifier over the static rules plus the dynamic
// rules generated from bundle, as the worker builds it after a fetch.
func auditClassifier(t *testing.T, bundle []byte) (*Classifier, *ATTCKLoader) {
	t.Helper()
	l := NewATTCKLoader(t.TempDir())
	if err := l.parseSTIX(bundle); err != nil {
		t.Fatal(err)
	}
	l.loaded = true
	return NewClassifier(l, nil), l
}

func auditClassify(c *Classifier, honeypot, eventType, command string) *database.Event {
	ev := &database.Event{Timestamp: time.Now().UTC(), Honeypot: honeypot, EventType: eventType,
		Command: command, SourceIP: "203.0.113.9"}
	c.Classify(context.Background(), ev)
	return ev
}

// Generated ATT&CK rules used to match any command or sensor text containing
// a word of the technique's name: a p0f "Windows 7 or 8" fingerprint became
// Application Window Discovery, a Suricata "invalid timestamp" alert Valid
// Accounts, "rm -rf /data/local/tmp/*" Local Accounts, Redis "KEYS *" SSH
// Authorized Keys. Code terms that a technique only cites as context
// ("ps shows cat /etc/passwd") or that several techniques cite labelled
// ordinary commands too.
func TestAuditDynamicRulesNoFalsePositives(t *testing.T) {
	c, _ := auditClassifier(t, auditBundle(t))
	cases := []struct{ honeypot, eventType, command string }{
		{"p0f", "os_fingerprint", "Windows 7 or 8"},
		{"p0f", "os_fingerprint", "Linux 3.11 and newer"},
		{"p0f", "os_fingerprint", "Mac OS X"},
		{"suricata", "alert", "SURICATA STREAM Packet with invalid timestamp"},
		{"suricata", "alert", "ET DROP Dshield Block Listed Source group 1"},
		{"suricata", "alert", "ET INFO Possible Kali Linux hostname in DHCP Request Packet"},
		{"mailoney", "mailoney.session", "HELO x\nAUTH LOGIN"},
		{"redishoneypot", "redishoneypot.command", "KEYS *"},
		{"redishoneypot", "redishoneypot.command", "INFO server"},
		{"adbhoney", "adbhoney.command", "cat /proc/cpuinfo"},
		{"adbhoney", "adbhoney.command", "rm -rf /data/local/tmp/*"},
		{"adbhoney", "adbhoney.command", "ls /data/local/tmp"},
		{"adbhoney", "adbhoney.command", "cat /etc/passwd"},
		{"adbhoney", "adbhoney.command", "iptables -F"},
		{"adbhoney", "adbhoney.command", "service sshd restart"},
		{"adbhoney", "adbhoney.command", "sleep 5"},
		{"adbhoney", "adbhoney.command", "ping -c 1 192.0.2.1"},
		{"adbhoney", "adbhoney.command", "cat /var/log/kern.log"},
		{"adbhoney", "adbhoney.command", "cd /dev/shm"},
		{"adbhoney", "adbhoney.command", "cat readme.txt"},
		{"adbhoney", "adbhoney.command", "cat ~/.bash_history"},
		{"adbhoney", "adbhoney.command", "source ~/.bashrc"},
		{"adbhoney", "adbhoney.command", "man useradd"},
		{"adbhoney", "adbhoney.command", "grep nohup app.log"},
		{"adbhoney", "adbhoney.command", "echo kubectl"},
		{"adbhoney", "adbhoney.command", "USERADD"},
		{"adbhoney", "adbhoney.command", "useradder --help"},
		{"adbhoney", "adbhoney.command", "echo MYHISTFILE"},
	}
	// The curated rules label what a category shows (iptables -F covers
	// tracks); the generated ones must add nothing to these.
	static := newTestClassifierT(t)
	for _, tc := range cases {
		ev := auditClassify(c, tc.honeypot, tc.eventType, tc.command)
		want := auditClassify(static, tc.honeypot, tc.eventType, tc.command)
		if ev.TechniqueID != want.TechniqueID {
			t.Errorf("%s %s %q labelled %s %s by a generated rule (curated: %q)", tc.honeypot, tc.eventType, tc.command, ev.TechniqueID, ev.TechniqueName, want.TechniqueID)
		}
	}
}

// The generated rules still label the shell commands their technique's code
// terms name, in command position, with the technique's tactic ID.
func TestAuditDynamicRulesMatchCommands(t *testing.T) {
	c, _ := auditClassifier(t, auditBundle(t))
	cases := []struct{ eventType, command, technique, tactic string }{
		{"adbhoney.command", "useradd -m -s /bin/bash backup", "T1136.001", "TA0003"},
		{"adbhoney.command", "/usr/sbin/useradd backup", "T1136.001", "TA0003"},
		{"adbhoney.command", "cd /tmp && useradd backup", "T1136.001", "TA0003"},
		{"adbhoney.command", "busybox nohup /data/local/tmp/x", "T1564.011", "TA0005"},
		{"command", "cd /tmp; nohup ./x >/dev/null 2>&1 &", "T1564.011", "TA0005"},
		{"adbhoney.command", "echo ExecStart=/tmp/.x >> /etc/systemd/system/x.service", "T1543.002", "TA0003"},
		{"adbhoney.command", "unset HISTFILE", "T1690", "TA0112"},
		{"adbhoney.command", "export  HISTFILESIZE=0", "T1690", "TA0112"},
		{"adbhoney.command", "docker ps -a", "T1059.013", "TA0002"},
		{"adbhoney.command", "sed -i s/PermitRootLogin.*/PermitRootLogin_yes/ /etc/ssh/sshd_config", "T1098.004", "TA0003"},
	}
	for _, tc := range cases {
		ev := auditClassify(c, "adbhoney", tc.eventType, tc.command)
		if ev.TechniqueID != tc.technique || ev.TacticID != tc.tactic {
			t.Errorf("%q: got %s (%s, tactic %q), want %s tactic %s", tc.command, ev.TechniqueID, ev.TechniqueName, ev.TacticID, tc.technique, tc.tactic)
		}
	}
}

// A deprecated technique is not loaded: it was replaced and its rule would
// only add stale labels (v18 still ships T1153 "Source").
func TestAuditParseSTIXSkipsDeprecated(t *testing.T) {
	_, l := auditClassifier(t, auditBundle(t))
	if _, ok := l.Get("T1153"); ok {
		t.Error("deprecated T1153 loaded")
	}
	if tech, ok := l.Get("T1136.001"); !ok || len(tech.TacticIDs) != 1 || tech.TacticIDs[0] != "TA0003" {
		t.Errorf("T1136.001 tactic IDs not filled: %+v", tech)
	}
	for _, r := range l.GenerateDynamicRules() {
		for _, cond := range r.Conditions {
			if _, err := regexp.Compile(cond.Pattern); err != nil {
				t.Errorf("%s: pattern does not compile: %v", r.TechniqueID, err)
			}
		}
	}
}

// TestAuditDynamicRulesOnATTCKBundle runs benign commands and sensor text
// through the rules generated from a real ATT&CK bundle (the worker's cached
// attck-enterprise.json). It is skipped unless QPOT_ATTCK_BUNDLE names one;
// QPOT_ATTCK_BENIGN may name a JSONL file of extra
// {"honeypot","event_type","command"} lines that must stay unlabelled.
func TestAuditDynamicRulesOnATTCKBundle(t *testing.T) {
	p := os.Getenv("QPOT_ATTCK_BUNDLE")
	if p == "" {
		t.Skip("QPOT_ATTCK_BUNDLE not set")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	c, l := auditClassifier(t, data)
	rules := l.GenerateDynamicRules()
	for _, r := range rules {
		t.Logf("%s %s %s", r.TechniqueID, r.Name, r.Conditions[len(r.Conditions)-1].Pattern)
	}
	t.Logf("%d dynamic rules", len(rules))
	type row struct {
		Honeypot  string `json:"honeypot"`
		EventType string `json:"event_type"`
		Command   string `json:"command"`
	}
	rows := []row{
		{"p0f", "os_fingerprint", "Windows 7 or 8"},
		{"p0f", "os_fingerprint", "Windows NT kernel"},
		{"suricata", "alert", "ET SCAN Potential SSH Scan"},
		{"suricata", "alert", "SURICATA STREAM Packet with invalid timestamp"},
		{"mailoney", "mailoney.session", "EHLO localhost"},
		{"redishoneypot", "redishoneypot.command", "CONFIG SET dbfilename backup.db"},
	}
	for _, cmd := range []string{
		"cat /proc/cpuinfo", "rm -rf /data/local/tmp/*", "pm list packages", "pm path com.ufo.miner",
		"input keyevent 26", "settings put global package_verifier_enable 0", "cat /etc/passwd",
		"iptables -F", "sleep 5", "ping -c 1 192.0.2.1", "tail -n 50 /var/log/kern.log", "cd /dev/shm",
		"cat readme.txt", "service sshd restart", "init 6", "hash -r", "ls -la", "ps aux", "top -n 1",
		"df -h", "mount", "dmesg", "ldd /bin/ls", "curl -s ifconfig.me", "wget -q http://192.0.2.1/x",
	} {
		rows = append(rows, row{"adbhoney", "adbhoney.command", cmd})
	}
	if extra := os.Getenv("QPOT_ATTCK_BENIGN"); extra != "" {
		f, err := os.Open(extra)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var r row
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				rows = append(rows, r)
			}
		}
	}
	// Techniques only a generated rule assigns (MergeRules drops generated
	// rules for techniques a static rule covers).
	dynamic := map[string]bool{}
	for _, r := range rules {
		dynamic[r.TechniqueID] = true
	}
	for _, r := range DefaultRules() {
		delete(dynamic, r.TechniqueID)
	}
	for _, r := range rows {
		ev := auditClassify(c, r.Honeypot, r.EventType, r.Command)
		if dynamic[ev.TechniqueID] {
			t.Errorf("%s %s %q labelled %s %s by a generated rule", r.Honeypot, r.EventType, r.Command, ev.TechniqueID, ev.TechniqueName)
		}
	}
}

// FuzzAuditDynamicPattern builds a generated rule's pattern from an arbitrary
// ATT&CK code span. The pattern must compile, and it may only match a
// command that contains the term.
func FuzzAuditDynamicPattern(f *testing.F) {
	for _, s := range [][2]string{
		{"useradd", "sudo useradd x"}, {"crontab -l", "crontab  -l"}, {"HISTFILE", "unset HISTFILE"},
		{"cat /etc/passwd", "cat /etc/passwd"}, {"/proc/<PID>/maps", "cat /proc/1/maps"},
		{"export HISTFILESIZE=0", "export HISTFILESIZE=0"}, {"a.b+c", "a.b+c"}, {"x(", "x("},
		{strings.Repeat("ab ", 400), strings.Repeat("ab ", 400)},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, span, cmd string) {
		for _, s := range codeSpans("`" + span + "`") {
			if strings.ContainsAny(s, "`\n") {
				t.Fatalf("code span %q keeps a delimiter", s)
			}
		}
		p := dynamicPattern([]string{span})
		if p == "" {
			return
		}
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatalf("span %q: pattern %q: %v", span, p, err)
		}
		term, _ := codeTerm(span)
		if re.MatchString(cmd) && !strings.Contains(cmd, strings.Fields(term)[0]) {
			t.Fatalf("span %q matched %q without its term", span, cmd)
		}
	})
}
