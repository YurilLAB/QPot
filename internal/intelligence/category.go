package intelligence

import (
	"regexp"
	"sort"
	"strings"

	"github.com/qpot/qpot/internal/database"
)

// Category is a plain-language attack category, shown beside the ATT&CK
// technique so a reader sees "Path traversal" rather than only T1190.
type Category struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// Category IDs. They are stored with events and used in API filters, so an
// ID never changes once released.
const (
	CatScanning            = "scanning"
	CatBruteForce          = "brute-force"
	CatExploitAttempt      = "exploit-attempt"
	CatPathTraversal       = "path-traversal"
	CatFileInclusion       = "file-inclusion"
	CatSQLInjection        = "sql-injection"
	CatXSS                 = "xss"
	CatCommandInjection    = "command-injection"
	CatCodeInjection       = "code-injection"
	CatSSRF                = "ssrf"
	CatConfigExposure      = "config-exposure"
	CatFileUpload          = "file-upload"
	CatWebShell            = "web-shell"
	CatRecon               = "recon"
	CatMalwareDownload     = "malware-download"
	CatPrivilegeEscalation = "privilege-escalation"
	CatPersistence         = "persistence"
	CatCredentialAccess    = "credential-access"
	CatDefenseEvasion      = "defense-evasion"
	CatCryptomining        = "cryptomining"
	CatBotnet              = "botnet"
	CatLateralMovement     = "lateral-movement"
	CatProxyAbuse          = "proxy-abuse"
	CatImpact              = "impact"
	CatICSAttack           = "ics-attack"
	CatAmplification       = "amplification"
	CatDatabaseAbuse       = "database-abuse"
	CatVoIPFraud           = "voip-fraud"
)

// categoryCatalogue lists every category in display order.
var categoryCatalogue = []Category{
	{CatScanning, "Scanning and probing", "Port scans, banner grabs, crawlers and vulnerability scanners looking around."},
	{CatBruteForce, "Login guessing", "Guessing passwords, password spraying and credential stuffing on any service."},
	{CatExploitAttempt, "Known-vulnerability exploit", "An exploit for a named vulnerability, with its CVE when it is known."},
	{CatPathTraversal, "Path traversal / file read", "Reading files outside the web root: ../ tricks, /etc/passwd, local file inclusion."},
	{CatFileInclusion, "Remote file inclusion", "Making the server load a remote file or a php:// or data:// stream."},
	{CatSQLInjection, "SQL injection", "SQL smuggled into a request to read or change a database."},
	{CatXSS, "Cross-site scripting", "Script smuggled into a page to run in a visitor's browser."},
	{CatCommandInjection, "Command injection", "Operating-system commands smuggled through a web or service parameter."},
	{CatCodeInjection, "Code / template injection", "Code smuggled into a template, expression or deserializer: SSTI, OGNL, JNDI, PHP eval."},
	{CatSSRF, "Server-side request forgery", "Making the server fetch internal addresses, such as the cloud metadata service."},
	{CatConfigExposure, "Secret and config hunting", "Looking for secrets and config files: .env, .git, wp-config backups, phpinfo, actuator."},
	{CatFileUpload, "File upload", "Pushing a file in: web-shell uploads, HTTP PUT, SCP, SFTP, FTP and ADB transfers."},
	{CatWebShell, "Web shell use", "Requests to a known web shell or a cmd= style shell."},
	{CatRecon, "Host reconnaissance", "Looking around after logging in: uname, whoami, CPU, memory and network checks."},
	{CatMalwareDownload, "Malware / tool download", "Fetching malware or tools with wget, curl, tftp or busybox, or writing one out with echo."},
	{CatPrivilegeEscalation, "Privilege escalation attempt", "Trying to become root: sudo or su, SUID hunting, kernel and polkit exploits."},
	{CatPersistence, "Persistence", "Staying in: SSH keys, cron jobs, services, new users, password changes, shell profiles."},
	{CatCredentialAccess, "Credential theft", "Stealing credentials: /etc/shadow, SSH keys, cloud credentials, history files."},
	{CatDefenseEvasion, "Covering tracks", "Clearing history and logs, turning off firewalls and security tools, killing rival malware."},
	{CatCryptomining, "Cryptomining", "Installing or running a cryptocurrency miner, or connecting to a mining pool."},
	{CatBotnet, "Botnet loader", "Mirai and Gafgyt style IoT loaders, busybox probes and DDoS bot installs."},
	{CatLateralMovement, "Spreading", "Scanning or logging in to other machines from the honeypot."},
	{CatProxyAbuse, "Proxy and relay abuse", "Using the honeypot as a relay: SSH port forwarding, open-proxy checks, SMTP relaying."},
	{CatImpact, "Destructive actions", "Wiping disks or data, rm -rf /, fork bombs, ransom notes and DoS tools."},
	{CatICSAttack, "Industrial control attack", "Reading, writing or commanding industrial controllers over Modbus, S7, BACnet and similar."},
	{CatAmplification, "DDoS amplification", "UDP reflection probes for DDoS amplification (DNS, NTP, SSDP and others)."},
	{CatDatabaseAbuse, "Database abuse", "Abusing a database server: Redis CONFIG SET, SLAVEOF and MODULE LOAD, Elasticsearch scripts, MSSQL xp_cmdshell."},
	{CatVoIPFraud, "VoIP abuse", "SIP scanning, registration guessing and toll fraud."},
}

// categorySpecificity orders an event's categories, most specific first:
// the kind of target or the named exploit before the generic technique, and
// the broad "someone knocked" categories last.
var categorySpecificity = []string{
	CatICSAttack, CatAmplification, CatVoIPFraud, CatDatabaseAbuse,
	CatExploitAttempt, CatWebShell, CatCryptomining, CatBotnet,
	CatCodeInjection, CatCommandInjection, CatSQLInjection, CatXSS, CatSSRF,
	CatFileInclusion, CatPathTraversal, CatConfigExposure, CatFileUpload,
	CatCredentialAccess, CatPrivilegeEscalation, CatPersistence, CatDefenseEvasion,
	CatImpact, CatLateralMovement, CatProxyAbuse, CatMalwareDownload,
	CatRecon, CatBruteForce, CatScanning,
}

var (
	categoryByID   = map[string]Category{}
	categoryRankOf = map[string]int{}
)

func init() {
	for _, c := range categoryCatalogue {
		categoryByID[c.ID] = c
	}
	for i, id := range categorySpecificity {
		categoryRankOf[id] = i
	}
}

// Categories returns every attack category in display order.
func Categories() []Category {
	return append([]Category(nil), categoryCatalogue...)
}

// IsCategory reports whether id is a category ID.
func IsCategory(id string) bool {
	_, ok := categoryByID[id]
	return ok
}

// CategoryLabel returns a category's label. A CVE ID stored after
// exploit-attempt, or an unknown value, is returned as it is.
func CategoryLabel(id string) string {
	if c, ok := categoryByID[id]; ok {
		return c.Label
	}
	return id
}

// IsCVE reports whether v is a CVE ID as Categorize stores it.
func IsCVE(v string) bool { return catCVEStored.MatchString(v) }

var catCVEStored = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

const (
	// catMaxField bounds the attacker text examined per field. Longer text
	// keeps its head and its tail, where the commands of a dropper are. The
	// signs of an attack sit in a request's first line or a command's start;
	// a larger bound only made hostile 30 KB payloads cost ~130 ms each.
	catMaxField = 8 << 10
	catHead     = 6 << 10
	// catMaxCategories and catMaxCVEs bound what one event stores.
	catMaxCategories = 10
	catMaxCVEs       = 2
)

// catSet collects one event's categories and the CVEs of its exploit.
type catSet struct {
	ids  map[string]bool
	cves []string
}

func (s *catSet) add(ids ...string) {
	if s.ids == nil {
		s.ids = map[string]bool{}
	}
	for _, id := range ids {
		s.ids[id] = true
	}
}

// exploit records an exploit attempt, naming its CVE when known.
func (s *catSet) exploit(cve string) {
	s.add(CatExploitAttempt)
	if cve == "" {
		return
	}
	cve = strings.ToUpper(cve)
	for _, c := range s.cves {
		if c == cve {
			return
		}
	}
	if len(s.cves) < catMaxCVEs && catCVEStored.MatchString(cve) {
		s.cves = append(s.cves, cve)
	}
}

// list returns the categories, most specific first, each CVE right after
// exploit-attempt.
func (s *catSet) list() []string {
	if len(s.ids) == 0 {
		return nil
	}
	ids := make([]string, 0, len(s.ids))
	for id := range s.ids {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return categoryRankOf[ids[i]] < categoryRankOf[ids[j]] })
	if len(ids) > catMaxCategories {
		ids = ids[:catMaxCategories]
	}
	out := make([]string, 0, len(ids)+len(s.cves))
	for _, id := range ids {
		out = append(out, id)
		if id == CatExploitAttempt {
			out = append(out, s.cves...)
		}
	}
	return out
}

// Categorize returns the attack categories of an event, most specific
// first; an exploit attempt for a known vulnerability is followed by its
// CVE ID. An event that matches nothing has none. It reads the event only.
//
// It prefers precision to coverage: each category comes from what the
// honeypot recorded (a shell command, a web request, a Redis command, a
// connection) and only where that field means what the pattern assumes, so
// "cd ../.." in an SSH session is not path traversal and an IDS signature
// that mentions wget is not a download.
func Categorize(ev *database.Event) []string {
	if ev == nil {
		return nil
	}
	return categorizeInput(newCatInput(ev))
}

// categorizeInput is Categorize over an event's prepared input, which the
// classifier's rules read too.
func categorizeInput(in *catInput) []string {
	var s catSet
	catByEvent(in, &s)
	if in.shell != "" {
		catShell(in, &s)
	}
	if in.web != "" {
		catWeb(in, &s)
	}
	if in.redis != "" {
		catRedis(in, &s)
	}
	if in.smtp != "" {
		catSMTP(in, &s)
	}
	if in.printer != "" {
		catPrinter(in, &s)
	}
	if strings.Contains(in.any, "xp_cmdshell") {
		s.add(CatDatabaseAbuse)
	}
	if in.fingerprint != "" && catScannerFingerprint.MatchString(in.fingerprint) {
		s.add(CatScanning)
	}
	return s.list()
}

// catInput is an event as the category patterns read it. The text fields
// are bounded and lower-cased; a field is empty when the honeypot does not
// put that kind of input there.
type catInput struct {
	hp, et, proto string
	user, pass    string
	// shell is a shell command line (cowrie, adbhoney, ssh-proxy), with its
	// case: a shell's commands, options and variables are case-sensitive,
	// so "USERADD" creates no account.
	shell string
	// web is a decoded web request (path, query, raw request); webRaw is
	// the same text before percent-decoding.
	web, webRaw string
	// redis is a Redis command line (redisRaw keeps its case); smtp an
	// SMTP line (mailoney); printer a PJL job (miniprint).
	redis, redisRaw, smtp, printer string
	// idsCategory is a Suricata alert's classtype description.
	idsCategory string
	// fingerprint is the client's self-description: an SSH client version
	// or an HTTP user agent.
	fingerprint string
	// any is every attacker-supplied field, for the few tokens that mean
	// the same wherever they appear.
	any string
}

// Honeypot groups. The collector (internal/instance/compose.go) puts a web
// honeypot's path and query, or its raw request, in the payload and a
// shell honeypot's typed line in the command.
var (
	catWebHoneypots = map[string]bool{
		"tanner": true, "wordpot": true, "go-pot": true, "hellpot": true, "galah": true,
		"h0neytr4p": true, "log4pot": true, "citrixhoneypot": true, "ciscoasa": true,
		"honeyaml": true, "elasticpot": true,
	}
	catShellHoneypots = map[string]bool{"cowrie": true, "adbhoney": true, "ssh-proxy": true}
	// catOtherHoneypots put something other than a shell line in the
	// command (a Redis or SMTP command, a DICOM verb, an IDS signature, an
	// OS fingerprint), or no command at all.
	catOtherHoneypots = map[string]bool{
		"conpot": true, "refrigeration": true, "dionaea": true, "heralding": true, "mailoney": true, "redishoneypot": true,
		"dicompot": true, "medpot": true, "ddospot": true, "sentrypeer": true, "ipphoney": true,
		"miniprint": true, "endlessh": true, "suricata": true, "p0f": true, "fatt": true, "canary": true,
	}
)

func newCatInput(ev *database.Event) *catInput {
	in := &catInput{
		hp:    strings.ToLower(strings.TrimSpace(ev.Honeypot)),
		et:    strings.ToLower(strings.TrimSpace(ev.EventType)),
		proto: strings.ToLower(strings.TrimSpace(ev.Protocol)),
		user:  catBound(ev.Username),
		pass:  catBound(ev.Password),
	}
	cmd := catBound(ev.Command)
	payload := catBound(string(ev.Payload))

	web := catWebHoneypots[in.hp] || in.proto == "http" || in.proto == "https" || strings.Contains(in.et, ".http.")
	switch {
	case in.hp == "redishoneypot":
		in.redisRaw = cmd
		in.redis = strings.ToLower(cmd)
	case in.hp == "mailoney":
		in.smtp = strings.ToLower(cmd + "\n" + payload)
	case in.hp == "miniprint":
		in.printer = strings.ToLower(cmd + "\n" + payload)
	case web:
		raw := payload
		if cmd != "" {
			raw += "\n" + cmd
		}
		if strings.TrimSpace(raw) != "" {
			in.webRaw = strings.ToLower(raw)
			in.web = catDecodeWeb(raw)
		}
	case cmd != "" && (catShellHoneypots[in.hp] || !catOtherHoneypots[in.hp]):
		in.shell = cmd
	}

	fp := []string{}
	if ev.Metadata != nil {
		for _, k := range []string{"version", "user_agent", "useragent", "http_user_agent"} {
			if v := ev.Metadata[k]; v != "" {
				fp = append(fp, catBound(v))
			}
		}
		if in.hp == "suricata" {
			in.idsCategory = strings.ToLower(catBound(ev.Metadata["category"]))
		}
	}
	in.fingerprint = strings.ToLower(strings.Join(fp, "\n"))
	in.any = strings.ToLower(strings.Join([]string{cmd, payload, in.fingerprint}, "\n"))
	return in
}

// catBound keeps at most catMaxField bytes of s: its head and its tail.
func catBound(s string) string {
	if len(s) <= catMaxField {
		return s
	}
	return s[:catHead] + "\n" + s[len(s)-(catMaxField-catHead):]
}

// catDecodeWeb turns a request into the text the web patterns read:
// percent-escapes (also double-encoded and %uXXXX) decoded, overlong UTF-8
// dots and slashes folded, "+" in the query read as a space, ${IFS} as a
// space, and everything lower-cased.
func catDecodeWeb(raw string) string {
	s := raw
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i] + strings.ReplaceAll(s[i:], "+", " ")
	}
	for i := 0; i < 3; i++ {
		d := catPercentDecode(s)
		if d == s {
			break
		}
		s = d
	}
	s = catOverlong.Replace(s)
	s = strings.ToLower(s)
	s = catIFS.ReplaceAllString(s, " ")
	return s
}

var (
	catOverlong = strings.NewReplacer("\xc0\xae", ".", "\xc0\xaf", "/", "\xc1\x9c", "\\", "\xe0\x80\xae", ".", "\xc0\x2e", ".", "\xc0\x2f", "/")
	catIFS      = regexp.MustCompile(`\$\{ifs\}|\$ifs(?:\$\d)?`)
)

// catPercentDecode decodes %XX and %uXXXX escapes, leaving malformed ones
// as they are (a lenient decoder: attackers rely on servers that are).
func catPercentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if r, ok := catHexValue(s[i+2 : i+6]); ok {
				b.WriteRune(rune(r))
				i += 5
				continue
			}
		}
		if i+2 < len(s) {
			if v, ok := catHexValue(s[i+1 : i+3]); ok {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func catHexValue(h string) (int, bool) {
	v := 0
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v*16 + int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = v*16 + int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// catMatchAny reports whether any of the patterns matches s.
func catMatchAny(s, lower string, res ...*regexp.Regexp) bool {
	for _, re := range res {
		if catMatch(re, s, lower) {
			return true
		}
	}
	return false
}
