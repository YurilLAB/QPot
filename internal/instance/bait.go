package instance

// bait.go: the files an attacker finds on a Cowrie persona, and the canaries
// planted in them.
//
// What attackers take after a shell on a Linux server (sources in
// doc/canary.md): credential harvesters read ~/.ssh (private
// keys, config, known_hosts), .bash_history (ssh/scp/rsync and database
// command lines), /etc/hosts, ~/.aws/credentials, .git-credentials, .netrc,
// .pgpass, .env files and database dumps (Kinsing's spre.sh, SSH-Snake,
// TeamTNT's aws2.sh and creds.sh, AndroxGh0st); people at the keyboard look
// for user files to take and run more commands where the files look lived in
// (Barron and Nikiforakis, ACSAC 2017). The image's persona engine renders the
// system (packages, units, /etc, the users and their dotfiles) but no history,
// no ~/.ssh and nothing to steal on the server personas.
//
// QPot adds an ops box's working state, consistent with the persona: root's
// SSH key and config for the database host, the backup script and its cron
// entry, the cloud or backup-host credentials it uses, a manual database dump,
// the shell histories that made all of it, and for the login user the
// cloud-init authorized_keys, a password typed at the prompt by mistake and,
// where the persona has git, a stored GitLab token. Everything is drawn per
// instance from the deception seed (names, hosts, addresses, which parts
// exist), so instances differ while a regenerated compose plants the same
// files.
//
// Every secret in them is a canary (PlantedCanaries, registered by the server
// in the canary store). None needs the QPot web server to be reachable: they
// trip on the honeypot channel, when the value shows up in a captured session
// of any QPot honeypot - a password in an SSH, telnet, FTP, SMTP or database
// login, a token or key typed in a command, the stolen SSH key offered in a
// public key login. Only the backup script's healthcheck URL also trips on the
// http channel, and only when canary.base_url names where the web server is
// reachable; without it the URL points into the persona's internal network.
//
// The plan is written as JSON and mounted read-only into the Cowrie container
// (baitPlanPath). The patch layer's core/qpot_bait.py adds it to the persona's
// tree when Cowrie loads it: it fills in what only the running persona knows
// ({{host}}, the host name it drew; {{date:...}}, the files' times, placed
// between the persona's installation and its boot as At says), resolves the
// owners in its /etc/passwd, gzips what is marked so and leaves alone a path
// the persona already has.

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
)

// baitPlanPath is where the Cowrie container reads the plan.
const baitPlanPath = "/home/cowrie/cowrie/qpot-bait.json"

// baitPlanVersion is the plan format qpot_bait.py reads.
const baitPlanVersion = 1

// baitPlan is what qpot_bait.py adds to a persona's tree.
type baitPlan struct {
	Version  int           `json:"version"`
	Dirs     []baitDir     `json:"dirs"`
	Files    []baitFile    `json:"files"`
	Links    []baitLink    `json:"links"`
	Programs []baitProgram `json:"programs"`
	// Hosts are the internal hosts the files name; Cowrie's ssh times out on
	// them as on a host it cannot reach.
	Hosts []baitHost `json:"hosts"`
}

// baitDir is a directory created where the persona has none.
type baitDir struct {
	Path  string  `json:"path"`
	Owner string  `json:"owner"`
	Mode  uint32  `json:"mode"`
	At    float64 `json:"at"`
}

// baitFile is a file. At places its time between the persona's installation
// (0) and its boot (1); Text may hold {{host}} and {{date:FMT}} (the file's
// own time), {{date:FMT@ID}} (the time of the file with that ID), each with an
// optional |OFFSET in seconds. Path may hold {{date:...}}.
type baitFile struct {
	ID    string  `json:"id,omitempty"`
	Path  string  `json:"path"`
	Owner string  `json:"owner"`
	Mode  uint32  `json:"mode"`
	At    float64 `json:"at"`
	// Offset moves the file's time by that many seconds (the history written
	// minutes before the reboot the persona booted from); never before the
	// installation.
	Offset int `json:"offset,omitempty"`
	// InPlace: the file is rewritten in place (a shell history, known_hosts),
	// so its directory keeps its own time.
	InPlace bool   `json:"in_place,omitempty"`
	Gzip    bool   `json:"gzip,omitempty"`
	Text    string `json:"text"`
}

// baitLink is a symbolic link owned by root.
type baitLink struct {
	Path   string  `json:"path"`
	Target string  `json:"target"`
	At     float64 `json:"at"`
}

// baitProgram is an installed program: a file of that size without contents,
// as the persona's own programs are.
type baitProgram struct {
	Path string  `json:"path"`
	Size int     `json:"size"`
	At   float64 `json:"at"`
}

// baitHost is an internal host of the files: the names ssh may be given for it.
type baitHost struct {
	Names []string `json:"names"`
	IP    string   `json:"ip"`
}

// baitSetting is the cowrie custom_config key that turns the bait off.
const baitSetting = "bait"

// baitOn reports whether cfg plants bait in Cowrie (custom_config bait=off
// turns it off).
func baitOn(cfg *config.Config) bool {
	if hp, ok := cfg.GetHoneypotConfig("cowrie"); ok {
		return strings.TrimSpace(hp.CustomConfig[baitSetting]) != "off"
	}
	return true
}

// PlantedCanaries returns the canaries this instance plants in its honeypots,
// for the canary store to watch. Empty when Cowrie is off, its bait is turned
// off or its persona is a device.
func PlantedCanaries(cfg *config.Config) []*canary.Canary {
	if cfg == nil {
		return nil
	}
	if hp, ok := cfg.GetHoneypotConfig("cowrie"); !ok || !hp.Enabled {
		return nil
	}
	_, planted := cowrieBait(cfg)
	return planted
}

// cowrieBaitJSON is the content of the plan file mounted into Cowrie.
// deployProfile asks for it on every call (the port map and the compose
// template call that many times per render), so a plan is built once per set
// of what it is drawn from and kept (baitCache).
func cowrieBaitJSON(cfg *config.Config) []byte {
	key := baitCacheKey(cfg)
	baitCache.Lock()
	b, ok := baitCache.json[key]
	baitCache.Unlock()
	if ok {
		return slices.Clone(b)
	}
	plan, _ := cowrieBait(cfg)
	b, err := json.MarshalIndent(plan, "", " ")
	if err != nil {
		// Only strings, numbers and slices of them: cannot fail.
		panic(fmt.Sprintf("bait plan: %v", err))
	}
	b = append(b, '\n')
	baitCache.Lock()
	if len(baitCache.json) >= baitCacheMax || baitCache.json == nil {
		baitCache.json = map[string][]byte{}
	}
	baitCache.json[key] = b
	baitCache.Unlock()
	return slices.Clone(b)
}

// baitCache holds the plans built last, by baitCacheKey.
var baitCache struct {
	sync.Mutex
	json map[string][]byte
}

// baitCacheMax bounds baitCache (a plan is about 200 KB).
const baitCacheMax = 16

// baitCacheKey is everything of cfg a plan is drawn from: the persona, whether
// the bait is on, the deception seed and the beacon base of the healthcheck.
func baitCacheKey(cfg *config.Config) string {
	return strings.Join([]string{cowriePersona(cfg), fmt.Sprint(baitOn(cfg)), deceptionSeed(cfg),
		baitBeaconBase(cfg.Canary.BaseURL)}, "\x00")
}

// cowrieBait returns the plan for cfg's Cowrie persona and the canaries in it.
func cowrieBait(cfg *config.Config) (baitPlan, []*canary.Canary) {
	empty := baitPlan{Version: baitPlanVersion, Dirs: []baitDir{}, Files: []baitFile{}, Links: []baitLink{},
		Programs: []baitProgram{}, Hosts: []baitHost{}}
	p, ok := cowriePersonaByID(cowriePersona(cfg))
	if !ok || !p.Server || !baitOn(cfg) {
		return empty, nil
	}
	s := newBaitScene(cfg, p)
	s.plan = empty
	s.build()
	return s.plan, s.canaries
}

// baitPerson is the admin whose keys and names the files carry.
type baitPerson struct {
	First, Last, Login string
}

// baitHostInfo is an internal host of the scene.
type baitHostInfo struct {
	Alias, FQDN, IP, User string
}

// baitScene is one instance's ops box: the choices every file agrees on.
type baitScene struct {
	cfg *config.Config
	p   tpotCowriePersona
	d   canary.Deriver

	el     bool // Red Hat family: dnf/yum, crond, unhashed known_hosts, umask 002
	home   string
	user   string
	org    string
	domain string
	admin  baitPerson

	db, backup, monitor baitHostInfo
	engine              string // "mysql" or "postgres"
	dbName, dbUser      string
	dbPass              string
	script              string // path of the backup script
	cronName            string
	cronMin, cronHour   int

	aws               bool
	awsID, awsSecret  string
	region, bucket    string
	awsProfile        string
	dump              bool
	dumpPath, dumpDir string
	git               bool
	gitUser, gitToken string
	gitRepo           string
	keyComment        string
	pingToken         string
	pingURL           string
	userPass          string
	smtpPass          string

	plan     baitPlan
	canaries []*canary.Canary
}

var (
	baitOrgs = []string{"altavia", "brisklane", "corvexa", "dunmore", "elmbridge", "fenwick", "galvaro",
		"hollisdale", "ironvale", "kelvara", "lumicor", "marlowe", "northgate", "orrinford", "pellucid",
		"quillon", "rowanby", "silvane", "tervola", "ulmara", "vantor", "wexley", "yarrowby", "zentra"}
	baitFirst = []string{"anna", "ben", "carla", "david", "elena", "felix", "grace", "hannah", "ivan", "julia",
		"karim", "lena", "marco", "nina", "oscar", "priya", "rafael", "sofia", "tomas", "vera", "wei", "yusuf",
		"zoe", "liam", "maya", "jonas", "aisha", "pavel", "ines", "kofi"}
	baitLast = []string{"ahmed", "becker", "costa", "dubois", "evans", "fischer", "garcia", "hansen", "ito",
		"jensen", "kowalski", "larsen", "moreau", "novak", "okafor", "petrov", "quinn", "rossi", "silva",
		"tanaka", "urban", "varga", "weber", "young", "zimmer", "lindqvist", "mendes", "obrien", "haas"}
	baitDBNames  = []string{"helpdesk", "billing", "crm", "inventory", "portal", "shop", "erp", "wiki", "timesheets", "assets"}
	baitRegions  = []string{"us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-west-2", "eu-central-1", "eu-north-1", "ap-southeast-2", "ca-central-1"}
	baitReasons  = []string{"pre-upgrade", "before-migration", "pre-release", "manual", "pre-schema-change"}
	baitGitRepos = []string{"ops/ansible", "ops/infra", "infra/terraform", "platform/deploy-scripts", "it/runbooks"}
)

// title capitalises a lower-case word.
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func newBaitScene(cfg *config.Config, p tpotCowriePersona) *baitScene {
	d := canary.NewDeriver(deceptionSeed(cfg)).Sub("cowrie-bait")
	s := &baitScene{cfg: cfg, p: p, d: d, user: p.User}
	s.el = p.Family == "rhel" || p.Family == "centos"
	s.home = "/home/" + p.User
	s.org = canary.Pick(d, "org", baitOrgs)
	s.domain = canary.Pick(d, "domain", []string{s.org + ".internal", s.org + ".lan", "corp." + s.org + ".internal"})
	s.admin.First = canary.Pick(d, "first", baitFirst)
	s.admin.Last = canary.Pick(d, "last", baitLast)
	s.admin.Login = canary.Pick(d, "login", []string{s.admin.First, s.admin.First[:1] + s.admin.Last,
		s.admin.First + "." + s.admin.Last})

	// The internal network: one /24 of a private range, a distinct address each.
	var subnet string
	switch r := d.Intn("net-class", 20); {
	case r < 12:
		subnet = fmt.Sprintf("10.%d.%d", d.Intn("net-a", 255), d.Intn("net-b", 255))
	case r < 17:
		subnet = fmt.Sprintf("172.%d.%d", 16+d.Intn("net-a", 16), d.Intn("net-b", 255))
	default:
		subnet = fmt.Sprintf("192.168.%d", 1+d.Intn("net-b", 254))
	}
	used := map[int]bool{}
	addr := func(label string) string {
		for i := 0; ; i++ {
			n := 5 + d.Intn(fmt.Sprintf("%s-%d", label, i), 246)
			if !used[n] {
				used[n] = true
				return fmt.Sprintf("%s.%d", subnet, n)
			}
		}
	}

	s.engine = canary.Pick(d, "engine", []string{"mysql", "postgres"})
	s.dbName = canary.Pick(d, "db-name", baitDBNames)
	s.dbUser = canary.Pick(d, "db-user", []string{"backup", "dump", "bkp", s.dbName + "_backup", "readonly"})
	alias := map[string][]string{"mysql": {"db01", "db-prod", "mysql01", "db1", "sql01"},
		"postgres": {"db01", "pg01", "pgsql-prod", "db-main", "postgres01"}}[s.engine]
	s.db.Alias = canary.Pick(d, "db-alias", alias)
	s.db.FQDN = s.db.Alias + "." + s.domain
	s.db.IP = addr("db-ip")
	s.db.User = canary.Pick(d, "db-ssh-user", []string{"backup", "root", "deploy", s.admin.Login})
	s.dbPass = d.Secret("db-pass", 18)

	s.aws = d.Intn("aws", 10) < 7
	if s.aws {
		s.awsID, s.awsSecret = d.AWSKeyPair("aws")
		s.region = canary.Pick(d, "region", baitRegions)
		s.bucket = canary.Pick(d, "bucket", []string{s.org + "-db-backups", s.org + "-backups",
			s.org + "-" + s.dbName + "-dumps", "backups-" + s.org})
		s.awsProfile = canary.Pick(d, "aws-profile", []string{"default", "default", "backup"})
	} else {
		s.backup.Alias = canary.Pick(d, "bk-alias", []string{"backup01", "nas01", "bkp01", "vault"})
		s.backup.FQDN = s.backup.Alias + "." + s.domain
		s.backup.IP = addr("bk-ip")
		s.backup.User = canary.Pick(d, "bk-user", []string{"backup", "bkp", "dumps"})
	}
	s.monitor.IP = addr("mon-ip")

	dir := canary.Pick(d, "script-dir", []string{"/usr/local/sbin", "/usr/local/bin", "/root/bin"})
	base := canary.Pick(d, "script-name", []string{"db-backup", "backup-db", "nightly-dump",
		map[string]string{"mysql": "mysql-backup", "postgres": "pg-backup"}[s.engine], "dump-" + s.dbName})
	s.script = dir + "/" + base + ".sh"
	s.cronName = base // cron.d skips names with a dot
	s.cronMin, s.cronHour = d.Intn("cron-min", 60), 1+d.Intn("cron-hour", 5)

	s.dump = d.Intn("dump", 10) < 8
	if s.dump {
		s.dumpDir = "/var/backups"
		if s.el {
			s.dumpDir = "/root" // Red Hat systems have no /var/backups
		}
		s.dumpPath = s.dumpDir + "/" + s.dbName + "-" + canary.Pick(d, "reason", baitReasons) + "-{{date:%Y%m%d}}.sql.gz"
	}
	// git is on the Ubuntu and Raspberry Pi OS personas only
	s.git = (p.Family == "ubuntu" || p.Family == "raspios") && d.Intn("git", 10) < 7
	if s.git {
		s.gitUser = canary.Pick(d, "git-user", []string{s.admin.Login, s.admin.First + "." + s.admin.Last, s.admin.First})
		s.gitToken = d.GitLabToken("git-token")
		s.gitRepo = canary.Pick(d, "git-repo", baitGitRepos)
	}
	s.keyComment = canary.Pick(d, "key-comment", []string{"backup@" + s.org, base, "root@" + s.org + "-ops",
		s.dbName + " backups"})
	s.pingToken = d.BeaconToken("ping")
	if b := baitBeaconBase(cfg.Canary.BaseURL); b != "" {
		s.pingURL = b + "/c/" + s.pingToken
	} else {
		s.pingURL = "http://" + s.monitor.IP + ":8000/ping/" + s.pingToken
	}
	s.userPass = d.HumanPassword("user-pass")
	s.smtpPass = d.AlnumSecret("smtp-pass", 16+d.Intn("smtp-len", 5))
	return s
}

// at returns a time of the timeline between from and to (fractions of the
// span between the persona's installation and its boot), jittered per
// instance.
func (s *baitScene) at(label string, from, to float64) float64 {
	return from + (to-from)*s.d.Float("at-"+label)
}

func (s *baitScene) dir(path, owner string, mode uint32, at float64) {
	s.plan.Dirs = append(s.plan.Dirs, baitDir{Path: path, Owner: owner, Mode: mode, At: at})
}

func (s *baitScene) file(f baitFile) {
	s.plan.Files = append(s.plan.Files, f)
}

// userMode is the mode a file the login user makes gets: Red Hat's umask 002
// for a user whose group is their own.
func (s *baitScene) userMode(mode uint32) uint32 {
	if s.el && mode&0o040 != 0 {
		return mode | 0o020
	}
	return mode
}

// plant registers a canary of the scene.
func (s *baitScene) plant(c *canary.Canary) {
	c.Planted = true
	c.Enabled = true
	s.canaries = append(s.canaries, c)
}

func (s *baitScene) memo(what string, paths ...string) string {
	shown := make([]string, len(paths))
	for i, p := range paths {
		shown[i] = unplaceholder(p)
	}
	return fmt.Sprintf("QPot bait in cowrie (%s): %s, in %s", s.p.ID, what, strings.Join(shown, ", "))
}

// baitBeaconBase is canary.base_url as the bait's healthcheck pings it: an
// http(s) origin with no character a shell script line or the plan's
// placeholders would trip on. Anything else (base_url is not validated when
// the config loads) leaves the healthcheck on the internal network.
func baitBeaconBase(raw string) string {
	b := strings.TrimRight(strings.TrimSpace(raw), "/")
	if b == "" || len(b) > 200 || strings.ContainsAny(b, "\"'`$\\{}<>|;&") {
		return ""
	}
	for _, r := range b {
		if r <= ' ' || r >= 0x7f {
			return ""
		}
	}
	u, err := url.Parse(b)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return b
}

// unplaceholder shows a path for the operator: a placeholder the honeypot
// fills when it loads the tree (a date of the persona drawn at its start) is
// unknown here, so it reads as a wildcard.
func unplaceholder(p string) string {
	var b strings.Builder
	for {
		open := strings.Index(p, "{{")
		if open < 0 {
			break
		}
		end := strings.Index(p[open:], "}}")
		if end < 0 {
			break
		}
		b.WriteString(p[:open])
		b.WriteByte('*')
		p = p[open+end+2:]
	}
	b.WriteString(p)
	return b.String()
}

// build fills the plan and the canaries.
func (s *baitScene) build() {
	s.sshFiles()
	s.backupJob()
	if s.aws {
		s.awsFiles()
	}
	if s.dump {
		s.dumpFile()
	}
	s.userFiles()
	s.rootHistory()

	s.plan.Hosts = append(s.plan.Hosts, baitHost{Names: []string{s.db.Alias, s.db.FQDN, s.db.IP}, IP: s.db.IP})
	if !s.aws {
		s.plan.Hosts = append(s.plan.Hosts, baitHost{Names: []string{s.backup.Alias, s.backup.FQDN, s.backup.IP},
			IP: s.backup.IP})
	}
	s.plan.Hosts = append(s.plan.Hosts, baitHost{Names: []string{s.monitor.IP}, IP: s.monitor.IP})

	pingPaths := []string{s.script, "/root/.bash_history"}
	s.plant(&canary.Canary{ID: s.d.ID("ping"), Kind: canary.KindWeb, Token: s.pingToken,
		Name: "cowrie bait: backup healthcheck URL", Memo: s.memo("the healthcheck URL "+s.pingURL, pingPaths...)})
}

// cloudInit reports whether the persona is a cloud image (cloud-init wrote
// the login user's authorized_keys and closed root's).
func (s *baitScene) cloudInit() bool {
	return s.p.Family != "raspios"
}

// sshFiles: root's key pair for the database host, its config and known
// hosts; the authorized_keys cloud-init wrote.
func (s *baitScene) sshFiles() {
	adminKey := s.d.Ed25519Key("admin-key").Public().(ed25519.PublicKey)
	adminComment := canary.Pick(s.d, "admin-comment", []string{
		s.admin.First + "@" + s.admin.First + "-laptop", s.admin.First + "@" + s.admin.First + "-thinkpad",
		s.admin.First + "." + s.admin.Last + "@MacBook-Pro.local",
		fmt.Sprintf("%s@ws-%03d", s.admin.Login, 10+s.d.Intn("ws", 190)), s.admin.First + "@" + s.admin.First + "-xps"})
	adminLine := canary.AuthorizedKey(canary.Ed25519PublicBlob(adminKey), adminComment)

	// the login user's ~/.ssh: cloud-init made it at the first boot
	s.dir(s.home+"/.ssh", s.user, 0o700, 0.001)
	if s.cloudInit() {
		s.file(baitFile{Path: s.home + "/.ssh/authorized_keys", Owner: s.user, Mode: 0o600, At: 0.001,
			Text: adminLine + "\n"})
	}

	keyAt := s.at("key", 0.04, 0.09)
	s.dir("/root/.ssh", "root", 0o700, 0.001)
	if s.cloudInit() {
		s.file(baitFile{Path: "/root/.ssh/authorized_keys", Owner: "root", Mode: 0o600, At: 0.001,
			Text: `no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="echo 'Please login as the user \"` +
				s.user + `\" rather than the user \"root\".';echo;sleep 10;exit 142" ` + adminLine + "\n"})
	}
	key := s.d.Ed25519Key("root-key")
	blob := canary.Ed25519PublicBlob(key.Public().(ed25519.PublicKey))
	check := binary.BigEndian.Uint32(s.d.Bytes("root-key-check", 4))
	s.file(baitFile{Path: "/root/.ssh/id_ed25519", Owner: "root", Mode: 0o600, At: keyAt,
		Text: string(canary.MarshalEd25519PrivateKey(key, s.keyComment, check))})
	pub := canary.AuthorizedKey(blob, s.keyComment)
	s.file(baitFile{Path: "/root/.ssh/id_ed25519.pub", Owner: "root", Mode: 0o644, At: keyAt, Text: pub + "\n"})
	s.plant(&canary.Canary{ID: s.d.ID("root-key"), Kind: canary.KindSSHKey,
		Name: "cowrie bait: root SSH key", PublicKey: pub,
		Values: []string{strings.Fields(pub)[1], canary.MD5Fingerprint(blob)},
		Memo:   s.memo("an SSH key, trips when it is offered in a login", "/root/.ssh/id_ed25519")})

	var cfg strings.Builder
	host := func(h baitHostInfo) {
		fmt.Fprintf(&cfg, "Host %s\n    HostName %s\n    User %s\n    IdentityFile ~/.ssh/id_ed25519\n\n", h.Alias, h.IP, h.User)
	}
	host(s.db)
	if !s.aws {
		host(s.backup)
	}
	cfg.WriteString("Host *\n    ServerAliveInterval 30\n    ConnectTimeout 10\n")
	s.file(baitFile{Path: "/root/.ssh/config", Owner: "root", Mode: 0o644, At: s.at("ssh-config", 0.09, 0.12),
		Text: cfg.String()})

	// known_hosts: the host keys of what root connected to, hashed where the
	// distribution's ssh_config says HashKnownHosts yes (Debian, Ubuntu)
	var kh strings.Builder
	ips := []string{s.db.IP}
	if !s.aws {
		ips = append(ips, s.backup.IP)
	}
	for i, ip := range ips {
		hk := canary.AuthorizedKey(canary.Ed25519PublicBlob(s.d.Ed25519Key("hostkey-"+ip).Public().(ed25519.PublicKey)), "")
		ec := canary.AuthorizedKey(s.d.ECDSAP256PublicBlob("hostkey-ec-"+ip), "")
		for j, k := range []string{hk, ec} {
			name := ip
			if !s.el {
				name = canary.HashKnownHost(s.d.Bytes(fmt.Sprintf("kh-salt-%d-%d", i, j), 20), ip)
			}
			kh.WriteString(name + " " + k + "\n")
		}
	}
	s.file(baitFile{Path: "/root/.ssh/known_hosts", Owner: "root", Mode: 0o644, At: s.at("known-hosts", 0.12, 0.2),
		InPlace: true, Text: kh.String()})
}

// backupJob: the nightly backup script and its cron entry.
func (s *baitScene) backupJob() {
	at := s.at("script", 0.12, 0.2)
	if strings.HasPrefix(s.script, "/root/bin/") {
		s.dir("/root/bin", "root", 0o755, at)
	}
	var dump string
	switch s.engine {
	case "mysql":
		dump = `mysqldump --single-transaction --routines -u $DB_USER -p'$DB_PASS' $DB_NAME`
	default:
		dump = `PGPASSWORD='$DB_PASS' pg_dump -h 127.0.0.1 -U $DB_USER $DB_NAME`
	}
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	if s.aws {
		fmt.Fprintf(&b, "# Nightly dump of %s from %s, streamed to S3.\n", s.dbName, s.db.Alias)
	} else {
		fmt.Fprintf(&b, "# Nightly dump of %s from %s, kept on %s.\n", s.dbName, s.db.Alias, s.backup.Alias)
	}
	b.WriteString("set -euo pipefail\n\n")
	fmt.Fprintf(&b, "DB_HOST=%s\nDB_NAME=%s\nDB_USER=%s\nDB_PASS='%s'\n", s.db.IP, s.dbName, s.dbUser, s.dbPass)
	b.WriteString("STAMP=$(date +%F)\n")
	if s.aws {
		fmt.Fprintf(&b, "DEST=s3://%s/%s\n", s.bucket, s.dbName)
		if s.awsProfile != "default" {
			fmt.Fprintf(&b, "export AWS_PROFILE=%s\n", s.awsProfile)
		}
	}
	fmt.Fprintf(&b, "PING_URL=%s\n\n", s.pingURL)
	fmt.Fprintf(&b, "ssh -i /root/.ssh/id_ed25519 -o BatchMode=yes %s@\"$DB_HOST\" \\\n  \"%s\" \\\n  | gzip -6 \\\n", s.db.User, dump)
	if s.aws {
		b.WriteString("  | aws s3 cp - \"$DEST/$DB_NAME-$STAMP.sql.gz\" --only-show-errors\n\n")
	} else {
		fmt.Fprintf(&b, "  | ssh -i /root/.ssh/id_ed25519 %s@%s \"cat > /srv/backups/$DB_NAME/$DB_NAME-$STAMP.sql.gz\"\n\n",
			s.backup.User, s.backup.IP)
	}
	b.WriteString("curl -fsS -m 10 --retry 3 -o /dev/null \"$PING_URL\"\n")
	s.file(baitFile{ID: "script", Path: s.script, Owner: "root", Mode: 0o750, At: at, Text: b.String()})

	cron := fmt.Sprintf("# %s nightly dump\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nMAILTO=\"\"\n%d %d * * * root %s >/dev/null 2>&1\n",
		s.dbName, s.cronMin, s.cronHour, s.script)
	s.file(baitFile{Path: "/etc/cron.d/" + s.cronName, Owner: "root", Mode: 0o644, At: s.at("cron", 0.2, 0.24), Text: cron})

	paths := []string{s.script, "/root/.bash_history"}
	s.plant(&canary.Canary{ID: s.d.ID("db-pass"), Kind: canary.KindCredential, Values: []string{s.dbPass},
		Name: "cowrie bait: " + s.dbName + " database password",
		Memo: s.memo("the "+s.engine+" password of "+s.dbUser+"@"+s.db.Alias, paths...)})
}

// awsCLIVersion is the AWS CLI v2 the persona's root installed with AWS's
// bundled installer (to /usr/local/aws-cli, linked from /usr/local/bin).
const awsCLIVersion = "2.9.19"

// awsFiles: ~/.aws of root (aws configure) and the CLI it used.
func (s *baitScene) awsFiles() {
	at := s.at("aws", 0.2, 0.25)
	s.dir("/root/.aws", "root", 0o755, at)
	s.file(baitFile{Path: "/root/.aws/config", Owner: "root", Mode: 0o600, At: at,
		Text: fmt.Sprintf("[%s]\nregion = %s\noutput = json\n", profileSection(s.awsProfile), s.region)})
	s.file(baitFile{Path: "/root/.aws/credentials", Owner: "root", Mode: 0o600, At: at,
		Text: fmt.Sprintf("[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n", s.awsProfile, s.awsID, s.awsSecret)})
	s.plant(&canary.Canary{ID: s.d.ID("aws"), Kind: canary.KindAWS, AccessKeyID: s.awsID, SecretAccessKey: s.awsSecret,
		Name: "cowrie bait: AWS access key", Memo: s.memo("the AWS key of the S3 backups", "/root/.aws/credentials")})

	inst := s.at("aws-install", 0.17, 0.2)
	v := "/usr/local/aws-cli/v2/" + awsCLIVersion
	for _, d := range []string{"/usr/local/aws-cli", "/usr/local/aws-cli/v2", v, v + "/bin", v + "/dist"} {
		s.dir(d, "root", 0o755, inst)
	}
	s.plan.Programs = append(s.plan.Programs,
		baitProgram{Path: v + "/dist/aws", Size: 6403432 + 8*s.d.Intn("aws-size", 4096), At: inst},
		baitProgram{Path: v + "/dist/aws_completer", Size: 6403432 + 8*s.d.Intn("aws-completer-size", 4096), At: inst})
	s.plan.Links = append(s.plan.Links,
		baitLink{Path: v + "/bin/aws", Target: "../dist/aws", At: inst},
		baitLink{Path: v + "/bin/aws_completer", Target: "../dist/aws_completer", At: inst},
		baitLink{Path: "/usr/local/aws-cli/v2/current", Target: v, At: inst},
		baitLink{Path: "/usr/local/bin/aws", Target: "/usr/local/aws-cli/v2/current/bin/aws", At: inst},
		baitLink{Path: "/usr/local/bin/aws_completer", Target: "/usr/local/aws-cli/v2/current/bin/aws_completer", At: inst})
}

// profileSection is a profile's section name in ~/.aws/config.
func profileSection(profile string) string {
	if profile == "default" {
		return profile
	}
	return "profile " + profile
}

// userFiles: the login user's history (a password typed at the prompt by
// mistake) and, where there is git, its stored GitLab token.
func (s *baitScene) userFiles() {
	var h []string
	pm := s.pkg()
	h = append(h, "sudo "+pm[0], "ls -la", "df -h")
	if s.git {
		gitAt := s.at("git", 0.25, 0.35)
		name := title(s.admin.First) + " " + title(s.admin.Last)
		email := s.admin.First + "." + s.admin.Last + "@" + s.domain
		s.file(baitFile{Path: s.home + "/.gitconfig", Owner: s.user, Mode: s.userMode(0o644), At: gitAt,
			Text: fmt.Sprintf("[user]\n\tname = %s\n\temail = %s\n[credential]\n\thelper = store\n", name, email)})
		s.file(baitFile{Path: s.home + "/.git-credentials", Owner: s.user, Mode: 0o600, At: gitAt + 0.001,
			Text: fmt.Sprintf("https://%s:%s@git.%s\n", s.gitUser, s.gitToken, s.domain)})
		h = append(h,
			fmt.Sprintf("git config --global user.name \"%s\"", name),
			"git config --global user.email "+email,
			"git config --global credential.helper store",
			fmt.Sprintf("git ls-remote https://git.%s/%s.git", s.domain, s.gitRepo))
		s.plant(&canary.Canary{ID: s.d.ID("git-token"), Kind: canary.KindCredential, Values: []string{s.gitToken},
			Name: "cowrie bait: GitLab token", Memo: s.memo("the GitLab token of "+s.gitUser, s.home+"/.git-credentials")})
	}
	h = append(h, "sudo -i", s.userPass, "sudo -i", "exit")
	s.file(baitFile{Path: s.home + "/.bash_history", Owner: s.user, Mode: 0o600, At: s.at("user-history", 0.9, 0.96),
		InPlace: true, Text: strings.Join(h, "\n") + "\n"})
	s.plant(&canary.Canary{ID: s.d.ID("user-pass"), Kind: canary.KindCredential, Values: []string{s.userPass},
		Name: "cowrie bait: " + s.user + " password",
		Memo: s.memo("the login password of "+s.user+" typed at the prompt", s.home+"/.bash_history")})
}

// pkg is the persona's package commands: update, list upgradable, upgrade.
func (s *baitScene) pkg() [3]string {
	switch s.p.Family {
	case "centos":
		return [3]string{"yum check-update", "yum check-update", "yum -y update"}
	case "rhel":
		return [3]string{"dnf check-update", "dnf check-update", "dnf -y upgrade"}
	default:
		return [3]string{"apt update", "apt list --upgradable", "apt upgrade -y"}
	}
}

// rootHistory: what root typed to set all of it up, then a manual dump before
// the last upgrade and the reboot the persona booted from.
func (s *baitScene) rootHistory() {
	pm := s.pkg()
	cronSvc := "cron"
	if s.el {
		cronSvc = "crond"
	}
	h := []string{
		"ssh-keygen -t ed25519 -C \"" + s.keyComment + "\"",
		"cat ~/.ssh/id_ed25519.pub",
		"ssh " + s.db.User + "@" + s.db.IP,
		"vi ~/.ssh/config",
		"ssh " + s.db.Alias,
	}
	if !s.aws {
		h = append(h, "ssh "+s.backup.Alias+" 'mkdir -p /srv/backups/"+s.dbName+"'")
	}
	profile := ""
	if s.awsProfile != "default" {
		profile = " --profile " + s.awsProfile
	}
	if s.aws {
		h = append(h, "aws --version", "aws configure"+profile, "aws s3 ls"+profile,
			"aws s3 ls s3://"+s.bucket+"/"+profile)
	}
	h = append(h,
		"vi "+s.script,
		"chmod 750 "+s.script,
		s.script,
	)
	if s.aws {
		h = append(h, "aws s3 ls s3://"+s.bucket+"/"+s.dbName+"/"+profile)
	} else {
		h = append(h, "ssh "+s.backup.Alias+" ls -lh /srv/backups/"+s.dbName+"/")
	}
	h = append(h,
		"curl -fsS -m 10 "+s.pingURL,
		"vi /etc/cron.d/"+s.cronName,
		"systemctl status "+cronSvc,
		"crontab -l",
		"df -h",
		"free -m",
	)
	if s.dump {
		var remote string
		switch s.engine {
		case "mysql":
			remote = "mysqldump --single-transaction -u " + s.dbUser + " -p'" + s.dbPass + "' " + s.dbName
		default:
			remote = "PGPASSWORD='" + s.dbPass + "' pg_dump -h 127.0.0.1 -U " + s.dbUser + " " + s.dbName
		}
		path := strings.ReplaceAll(s.dumpPath, "{{date:%Y%m%d}}", "{{date:%Y%m%d@dump}}")
		h = append(h,
			"ssh "+s.db.User+"@"+s.db.IP+" \""+remote+"\" | gzip > "+path,
			"ls -lh "+s.dumpDir+"/",
			"zcat "+path+" | head -40",
		)
	}
	h = append(h, pm[0], pm[1], pm[2], "uptime", "reboot")
	// bash writes the history as the reboot ends the session: minutes before the boot
	s.file(baitFile{Path: "/root/.bash_history", Owner: "root", Mode: 0o600, At: 1,
		Offset: -(60 + s.d.Intn("reboot", 600)), InPlace: true, Text: strings.Join(h, "\n") + "\n"})
}
