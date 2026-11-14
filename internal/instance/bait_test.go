package instance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
)

// baitCfg is an instance with Cowrie on as persona.
func baitCfg(id, persona string) *config.Config {
	cfg := config.Default("bait")
	cfg.QPotID = id
	enableOnly(cfg, "cowrie")
	hp := cfg.Honeypots["cowrie"]
	hp.CustomConfig = map[string]string{"persona": persona}
	cfg.Honeypots["cowrie"] = hp
	return cfg
}

// baitPlaceholder is the grammar qpot_bait.py fills in (its PLACEHOLDER).
var baitPlaceholder = regexp.MustCompile(`\{\{(?:(host)|date:([^{}|@]{1,40})(?:@([a-z0-9_-]{1,32}))?(?:\|(-?[0-9]{1,10}))?)\}\}`)

// watched returns the values a canary trips on.
func watched(c *canary.Canary) []string {
	switch c.Kind {
	case canary.KindAWS:
		return []string{c.AccessKeyID, c.SecretAccessKey}
	case canary.KindWeb:
		return []string{c.Token}
	}
	return c.Values
}

func serverPersonas() []tpotCowriePersona {
	var out []tpotCowriePersona
	for _, p := range tpotCowriePersonas {
		if p.Server {
			out = append(out, p)
		}
	}
	return out
}

// TestBaitStableAndUnique: a regenerated compose plants the same files with the
// same canaries; another instance shares no canary value with it.
func TestBaitStableAndUnique(t *testing.T) {
	seen := map[string]string{}
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("qp_%024d", i)
		p := serverPersonas()[i%len(serverPersonas())]
		cfg := baitCfg(id, p.ID)
		a, b := cowrieBaitJSON(cfg), cowrieBaitJSON(baitCfg(id, p.ID))
		if string(a) != string(b) {
			t.Fatalf("%s: plan differs between two generations", id)
		}
		ca, cb := PlantedCanaries(cfg), PlantedCanaries(baitCfg(id, p.ID))
		ja, _ := json.Marshal(ca)
		jb, _ := json.Marshal(cb)
		if string(ja) != string(jb) || len(ca) < 4 {
			t.Fatalf("%s: canaries differ between two generations or too few (%d)", id, len(ca))
		}
		for _, c := range ca {
			for _, v := range watched(c) {
				if other, dup := seen[v]; dup {
					t.Fatalf("value of %s also planted by %s", id, other)
				}
				seen[v] = id
			}
			if seen[c.ID] != "" {
				t.Fatalf("canary ID %s reused", c.ID)
			}
			seen[c.ID] = id
		}
	}
}

// TestBaitOnlyOnServers: the devices get none (a router has no ops box's
// files), nor does an instance with bait=off or without Cowrie.
func TestBaitOnlyOnServers(t *testing.T) {
	for _, p := range tpotCowriePersonas {
		cfg := baitCfg("qp_devices000000000000000000", p.ID)
		plan, planted := cowrieBait(cfg)
		if p.Server != (len(plan.Files) > 0) || p.Server != (len(planted) > 0) {
			t.Errorf("%s: %d files, %d canaries", p.ID, len(plan.Files), len(planted))
		}
		// the device plan is still a plan qpot_bait.py reads (lists, not null)
		if !strings.Contains(string(cowrieBaitJSON(cfg)), `"files": [`) {
			t.Errorf("%s: plan without a files list", p.ID)
		}
	}
	cfg := baitCfg("qp_off0000000000000000000000", "ubuntu-noble")
	cfg.Honeypots["cowrie"].CustomConfig[baitSetting] = "off"
	if plan, planted := cowrieBait(cfg); len(plan.Files) > 0 || len(planted) > 0 || PlantedCanaries(cfg) != nil {
		t.Error("bait=off still plants")
	}
	cfg = baitCfg("qp_nocowrie00000000000000000", "ubuntu-noble")
	enableOnly(cfg, "heralding")
	if PlantedCanaries(cfg) != nil {
		t.Error("canaries planted without Cowrie")
	}
	if PlantedCanaries(nil) != nil {
		t.Error("canaries of no config")
	}
	if err := CheckSetting("cowrie", baitSetting, "maybe"); err == nil {
		t.Error("bait=maybe accepted")
	}
	if err := CheckSetting("cowrie", baitSetting, "off"); err != nil {
		t.Error(err)
	}
}

// TestBaitPlanWellFormed checks every plan of many instances for what
// qpot_bait.py needs and what a real system shows: placeholders it can fill,
// references to files that exist, absolute clean paths, owners that are root
// or the persona's user, private files 0600, cron.d names without a dot.
func TestBaitPlanWellFormed(t *testing.T) {
	for i := 0; i < 60; i++ {
		p := serverPersonas()[i%len(serverPersonas())]
		cfg := baitCfg(fmt.Sprintf("qp_wellformed%015d", i), p.ID)
		plan, planted := cowrieBait(cfg)
		checkBaitPlan(t, p, plan, planted)
	}
}

// checkBaitPlan fails t when the plan of persona p or its canaries break what
// TestBaitPlanWellFormed checks.
func checkBaitPlan(t *testing.T, p tpotCowriePersona, plan baitPlan, planted []*canary.Canary) {
	t.Helper()
	ids := map[string]bool{}
	for _, f := range plan.Files {
		if f.ID != "" {
			ids[f.ID] = true
		}
	}
	paths := map[string]bool{}
	for _, f := range plan.Files {
		where := p.ID + ":" + f.Path
		for _, m := range regexp.MustCompile(`\{\{.*?\}\}`).FindAllString(f.Text+f.Path, -1) {
			sub := baitPlaceholder.FindStringSubmatch(m)
			if sub == nil || sub[0] != m {
				t.Fatalf("%s: placeholder %q qpot_bait.py does not fill", where, m)
			}
			if sub[3] != "" && !ids[sub[3]] {
				t.Fatalf("%s: %q names no file", where, m)
			}
		}
		clean := baitPlaceholder.ReplaceAllString(f.Path, "x")
		if !strings.HasPrefix(f.Path, "/") || path.Clean(clean) != clean || paths[f.Path] {
			t.Fatalf("%s: bad or repeated path", where)
		}
		paths[f.Path] = true
		if f.Owner != "root" && f.Owner != p.User {
			t.Fatalf("%s: owner %s", where, f.Owner)
		}
		if strings.HasPrefix(f.Path, "/root/") && f.Owner != "root" ||
			strings.HasPrefix(f.Path, "/home/") && !strings.HasPrefix(f.Path, "/home/"+p.User+"/") {
			t.Fatalf("%s: in the wrong home (%s)", where, f.Owner)
		}
		base := path.Base(f.Path)
		if (base == "id_ed25519" || base == "credentials" || base == ".git-credentials" ||
			base == ".bash_history" || base == "authorized_keys") && f.Mode != 0o600 {
			t.Fatalf("%s: mode %o", where, f.Mode)
		}
		if strings.HasPrefix(f.Path, "/etc/cron.d/") && strings.Contains(base, ".") {
			t.Fatalf("%s: cron skips a file with a dot", where)
		}
		if f.At < 0 || f.At > 1 || f.Offset > 0 {
			t.Fatalf("%s: at %v offset %d outside install..boot", where, f.At, f.Offset)
		}
		if strings.Contains(f.Text, "\r") {
			t.Fatalf("%s: CR in a file", where)
		}
	}
	for _, d := range plan.Dirs {
		if !strings.HasPrefix(d.Path, "/") || path.Clean(d.Path) != d.Path || (d.Owner != "root" && d.Owner != p.User) {
			t.Fatalf("%s: dir %+v", p.ID, d)
		}
	}
	// every planted value is in the files, and each canary is a planted one
	var all strings.Builder
	for _, f := range plan.Files {
		all.WriteString(f.Text)
	}
	for _, c := range planted {
		if !c.Planted || !c.Enabled || !strings.HasPrefix(c.ID, "cnry_") || !strings.HasPrefix(c.Memo, "QPot bait in cowrie ("+p.ID+")") {
			t.Fatalf("%s: canary %+v", p.ID, c)
		}
		// the operator reads the memo: no placeholder the honeypot fills
		if strings.Contains(c.Memo+c.Name, "{{") || strings.Contains(c.Memo+c.Name, "}}") {
			t.Fatalf("%s: %s shows a placeholder: %s", p.ID, c.Name, c.Memo)
		}
		for _, v := range watched(c) {
			if len(v) < canary.MinWatchLen {
				t.Fatalf("%s: %s value too short to be watched", p.ID, c.Name)
			}
			// the SSH key's MD5 fingerprint is not in a file, its key is
			if c.Kind == canary.KindSSHKey && strings.Contains(v, ":") {
				continue
			}
			if !strings.Contains(all.String(), v) {
				t.Fatalf("%s: %s is not in any file", p.ID, c.Name)
			}
		}
	}
}

// file returns the plan's file at p, or fails.
func baitFileAt(t *testing.T, plan baitPlan, p string) baitFile {
	t.Helper()
	for _, f := range plan.Files {
		if f.Path == p {
			return f
		}
	}
	t.Fatalf("no %s in the plan", p)
	return baitFile{}
}

// baitFileWithPrefix returns the one file of the plan under prefix.
func baitFileWithPrefix(t *testing.T, plan baitPlan, prefix string) baitFile {
	t.Helper()
	var found []baitFile
	for _, f := range plan.Files {
		if strings.HasPrefix(f.Path, prefix) {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d files under %s in the plan, want 1", len(found), prefix)
	}
	return found[0]
}

// TestBaitConsistent: the files agree with each other and with the persona
// (what a person comparing them would check).
func TestBaitConsistent(t *testing.T) {
	kinds := map[string]bool{}
	for i := 0; i < 60; i++ {
		p := serverPersonas()[i%len(serverPersonas())]
		cfg := baitCfg(fmt.Sprintf("qp_consistent%015d", i), p.ID)
		s := newBaitScene(cfg, p)
		plan, planted := cowrieBait(cfg)
		el := p.Family == "rhel" || p.Family == "centos"
		rootHist := baitFileAt(t, plan, "/root/.bash_history").Text
		script := baitFileAt(t, plan, s.script).Text
		cron := baitFileAt(t, plan, "/etc/cron.d/"+s.cronName).Text
		if !strings.Contains(cron, " root "+s.script+" ") || !strings.Contains(rootHist, "vi "+s.script) {
			t.Fatalf("%s: cron entry or history does not name the script %s", p.ID, s.script)
		}
		if !strings.Contains(script, "DB_PASS='"+s.dbPass+"'") || !strings.Contains(script, s.db.IP) {
			t.Fatalf("%s: script without its database", p.ID)
		}
		cfgFile := baitFileAt(t, plan, "/root/.ssh/config").Text
		if !strings.Contains(cfgFile, "Host "+s.db.Alias+"\n    HostName "+s.db.IP+"\n    User "+s.db.User) ||
			!strings.Contains(rootHist, "ssh "+s.db.Alias+"\n") || !strings.Contains(script, s.db.User+`@"$DB_HOST"`) {
			t.Fatalf("%s: ssh config, history and script disagree on the database host", p.ID)
		}
		kh := baitFileAt(t, plan, "/root/.ssh/known_hosts").Text
		if el == strings.HasPrefix(kh, "|1|") {
			t.Fatalf("%s: known_hosts hashed=%v on a Red Hat=%v persona", p.ID, strings.HasPrefix(kh, "|1|"), el)
		}
		if el && !strings.HasPrefix(kh, s.db.IP+" ssh-ed25519 ") {
			t.Fatalf("%s: known_hosts does not list the database host", p.ID)
		}
		pkg := map[string]string{"centos": "yum -y update", "rhel": "dnf -y upgrade"}[p.Family]
		if pkg == "" {
			pkg = "apt upgrade -y"
		}
		if !strings.Contains(rootHist, pkg+"\nuptime\nreboot\n") {
			t.Fatalf("%s: history does not upgrade with the persona's package manager", p.ID)
		}
		if el != strings.Contains(rootHist, "systemctl status crond") {
			t.Fatalf("%s: cron service of another family", p.ID)
		}
		// the private key is the SSH key canary's, its .pub line the same key
		key, err := ssh.ParseRawPrivateKey([]byte(baitFileAt(t, plan, "/root/.ssh/id_ed25519").Text))
		if err != nil {
			t.Fatalf("%s: private key: %v", p.ID, err)
		}
		pub, err := ssh.NewPublicKey(key.(*ed25519.PrivateKey).Public())
		if err != nil {
			t.Fatal(err)
		}
		blob := strings.Fields(string(ssh.MarshalAuthorizedKey(pub)))[1]
		if !strings.HasPrefix(baitFileAt(t, plan, "/root/.ssh/id_ed25519.pub").Text, "ssh-ed25519 "+blob+" "+s.keyComment+"\n") {
			t.Fatalf("%s: .pub is not the private key's", p.ID)
		}
		var keyCanary *canary.Canary
		for _, c := range planted {
			kinds[string(c.Kind)] = true
			if c.Kind == canary.KindSSHKey {
				keyCanary = c
			}
		}
		if keyCanary == nil || keyCanary.Values[0] != blob || keyCanary.Values[1] != ssh.FingerprintLegacyMD5(pub) {
			t.Fatalf("%s: the SSH key canary does not watch the planted key", p.ID)
		}
		if s.dump {
			dump := baitFileAt(t, plan, s.dumpPath)
			if !dump.Gzip || !strings.Contains(dump.Text, s.smtpPass) || dump.Owner != "root" {
				t.Fatalf("%s: dump %+v", p.ID, dump.Path)
			}
			hist := strings.ReplaceAll(s.dumpPath, "{{date:%Y%m%d}}", "{{date:%Y%m%d@dump}}")
			if !strings.Contains(rootHist, "| gzip > "+hist+"\n") || strings.HasPrefix(s.dumpPath, "/var/backups/") == el {
				t.Fatalf("%s: history does not make the dump %s", p.ID, s.dumpPath)
			}
		}
		if s.git && !(p.Family == "ubuntu" || p.Family == "raspios") {
			t.Fatalf("%s: git files on a persona without git", p.ID)
		}
		if s.aws {
			if !slices.ContainsFunc(plan.Links, func(l baitLink) bool { return l.Path == "/usr/local/bin/aws" }) {
				t.Fatalf("%s: credentials of an aws that is not installed", p.ID)
			}
			if !strings.Contains(rootHist, "aws configure") || !strings.Contains(script, "aws s3 cp - ") {
				t.Fatalf("%s: aws credentials nothing uses", p.ID)
			}
		} else if strings.Contains(rootHist, "aws ") || strings.Contains(script, "aws ") {
			t.Fatalf("%s: aws used without credentials", p.ID)
		}
		user := baitFileAt(t, plan, s.home+"/.bash_history").Text
		if !strings.Contains(user, "sudo -i\n"+s.userPass+"\n") {
			t.Fatalf("%s: user history without the password typed at the prompt", p.ID)
		}
		// the history is written minutes before the boot, after the files it made
		h := baitFileAt(t, plan, "/root/.bash_history")
		if h.At != 1 || h.Offset > -60 || h.Offset < -660 {
			t.Fatalf("%s: root history at %v%+d", p.ID, h.At, h.Offset)
		}
	}
	for _, k := range []string{"aws", "credential", "ssh-key", "web"} {
		if !kinds[k] {
			t.Errorf("no instance planted a %s canary", k)
		}
	}
}

// TestBaitPingURL: with canary.base_url the healthcheck pings the web server's
// beacon (the http channel); without, an address of the internal network.
func TestBaitPingURL(t *testing.T) {
	cfg := baitCfg("qp_pingurl00000000000000000", "debian-bookworm")
	s := newBaitScene(cfg, serverPersonas()[3])
	if !strings.HasPrefix(s.pingURL, "http://"+s.monitor.IP+":8000/ping/") {
		t.Fatalf("ping URL without base_url: %s", s.pingURL)
	}
	cfg.Canary.BaseURL = "https://hc.example.net/"
	s = newBaitScene(cfg, serverPersonas()[3])
	var web *canary.Canary
	for _, c := range PlantedCanaries(cfg) {
		if c.Kind == canary.KindWeb {
			web = c
		}
	}
	if web == nil || s.pingURL != "https://hc.example.net/c/"+web.Token || web.URL(cfg.Canary.BaseURL) != s.pingURL {
		t.Fatalf("ping URL %s, canary %+v", s.pingURL, web)
	}
	if !strings.Contains(baitFileAt(t, mustPlan(cfg), s.script).Text, "PING_URL="+s.pingURL+"\n") {
		t.Fatal("script does not ping the beacon")
	}
}

// TestBaitCacheFollowsConfig: the plan cowrieBaitJSON keeps is the one the
// config draws now: another instance, persona, base_url or bait=off gets its
// own, and a caller changing its copy changes no later one.
func TestBaitCacheFollowsConfig(t *testing.T) {
	variants := []func(*config.Config){
		func(*config.Config) {},
		func(c *config.Config) { c.QPotID = "qp_cachekey0000000000000001" },
		func(c *config.Config) { c.Honeypots["cowrie"].CustomConfig["persona"] = "rhel-9" },
		func(c *config.Config) { c.Canary.BaseURL = "https://hc.example.net" },
		func(c *config.Config) { c.Honeypots["cowrie"].CustomConfig[baitSetting] = "off" },
	}
	seen := map[string]bool{}
	for round := 0; round < 3; round++ {
		for i, v := range variants {
			cfg := baitCfg("qp_cachekey0000000000000000", "ubuntu-noble")
			v(cfg)
			plan, _ := cowrieBait(cfg)
			fresh, _ := json.MarshalIndent(plan, "", " ")
			got := cowrieBaitJSON(cfg)
			if !bytes.Equal(got, append(fresh, '\n')) {
				t.Fatalf("round %d, variant %d: the kept plan is not the config's", round, i)
			}
			seen[string(got)] = true
			got[0] = 'X'
		}
	}
	if len(seen) != len(variants) {
		t.Fatalf("%d different plans for %d configs", len(seen), len(variants))
	}
}

func mustPlan(cfg *config.Config) baitPlan {
	p, _ := cowrieBait(cfg)
	return p
}

// TestIndustrialBaitReferencesMatchDevice checks the separately archived asset
// against the selected device for every OS/role combination. A meter, BMC or
// building controller must not turn into an invented pump PLC in its files.
func TestIndustrialBaitReferencesMatchDevice(t *testing.T) {
	for _, p := range serverPersonas() {
		for _, device := range ConpotProfiles() {
			t.Run(p.ID+"/"+device.ID, func(t *testing.T) {
				cfg := baitCfg("qp_industrial00000000000001", p.ID)
				cfg.Honeypots["cowrie"].CustomConfig[baitProfileSetting] = "industrial"
				hp := cfg.Honeypots["conpot"]
				hp.CustomConfig = map[string]string{"template": device.ID}
				cfg.Honeypots["conpot"] = hp // A disabled Conpot may still have an archive reference.
				plan, planted := cowrieBait(cfg)
				checkBaitPlan(t, p, plan, planted)
				var inventory industrialInventory
				if err := json.Unmarshal([]byte(baitFileAt(t, plan, industrialRoot+"/inventory.json").Text), &inventory); err != nil {
					t.Fatal(err)
				}
				if inventory.Version != 1 || inventory.SourceHost != "{{host}}" || inventory.RecordType != "maintenance reference" || len(inventory.Assets) != 1 {
					t.Fatalf("invalid reference inventory: %+v", inventory)
				}
				// What the device calls itself is the device's to say (a BMC
				// may be "node16-ipmi"); QPot's name for the profile is not.
				site := conpotSiteOf(cfg)
				for _, f := range plan.Files {
					text := f.Text
					if site.Name != "" {
						text = strings.ReplaceAll(strings.ReplaceAll(text, site.Name, ""), strings.ToLower(site.Name), "")
					}
					if strings.Contains(text, "reference_profile") || strings.Contains(text, device.ID) {
						t.Fatalf("attacker-facing archive exposes internal profile metadata: %s", f.Path)
					}
				}
				a := inventory.Assets[0]
				// The archive names the device as the device names itself
				// (TestConpotSiteMirror holds conpotSiteOf to the container).
				if a.Name != site.Name || a.Site != site.Facility || a.Location != site.Location || a.Contact != site.Contact ||
					a.Domain != site.Domain || !slices.Equal(a.Tanks, site.Tanks) || (a.ReportsTo != nil) != (site.ReportsTo != "") ||
					(a.ReportsTo != nil && (a.ReportsTo.Host != site.ReportsTo || a.ReportsTo.Address != site.ReportsToIP)) {
					t.Fatalf("the archive names the device %+v, the device says %+v", a, site)
				}
				said := map[string]bool{"IEC104": site.Name != "" && site.Facility != "" && site.Location != "" && site.Contact != "",
					"iccp": site.Domain != "", "ipmi": site.Name != "", "kamstrup_382": a.ReportsTo != nil,
					"building_automation": site.Location != "", "guardian_ast": site.Name != "" && len(site.Tanks) >= 3}
				if ok, named := said[device.ID]; named && !ok {
					t.Fatalf("the archive leaves out what a %s reports of itself: %+v", device.ID, a)
				}
				handover := baitFileAt(t, plan, industrialRoot+"/maintenance/handover.txt").Text
				if strings.Contains(handover, "%!") || !strings.Contains(handover, "Reference asset: "+a.ID+" ("+device.Model+"), "+device.Category+"\n"+industrialSiteNotes(site)+"Communications record: "+industrialRoot+"/exports/"+a.ID+"/communications.csv\nInventory: "+industrialRoot+"/inventory.json\n") {
					t.Fatalf("the handover does not read as written:\n%s", handover)
				}
				snapshot := baitFileWithPrefix(t, plan, industrialRoot+"/backups/").Text
				for _, v := range []string{site.Name, site.Facility, site.Location, site.Contact, site.Domain, site.ReportsTo, site.ReportsToIP} {
					if v != "" && (!strings.Contains(handover, v) || !strings.Contains(snapshot, v)) {
						t.Fatalf("%q is in the inventory and not in the handover or the stored snapshot", v)
					}
				}
				for _, tank := range site.Tanks {
					if !strings.Contains(handover, fmt.Sprintf("Tank %d: %s, %d gal nominal\n", tank.Number, tank.Product, tank.CapacityGal)) {
						t.Fatalf("tank %+v is not in the handover", tank)
					}
				}
				// A name that can be a host name resolves to the asset.
				if alias := strings.ToLower(site.Name); reHostLabel.MatchString(site.Name) != slices.Contains(plan.Hosts[1].Names, alias) {
					t.Fatalf("hosts entry of the asset: %v, device name %q", plan.Hosts[1].Names, site.Name)
				}
				if a.Model != device.Model || a.Role != device.Category || !slices.Equal(a.Protocols, device.Protocols) ||
					len(a.Endpoints) != len(device.TCP)+len(device.UDP) {
					t.Fatalf("archive contradicts device: %+v vs %+v", a, device)
				}
				if ip := net.ParseIP(a.Address); ip == nil || !ip.IsPrivate() {
					t.Fatalf("asset has no synthetic private address: %q", a.Address)
				}
				rows, err := csv.NewReader(strings.NewReader(baitFileAt(t, plan, industrialRoot+"/exports/"+a.ID+"/communications.csv").Text)).ReadAll()
				if err != nil || len(rows) != len(a.Endpoints)+1 {
					t.Fatalf("communications CSV: %v; %v", rows, err)
				}
				for i, ep := range a.Endpoints {
					ports := device.TCP
					if ep.Transport == "udp" {
						ports = device.UDP
					} else if ep.Transport != "tcp" {
						t.Fatalf("unknown transport %q", ep.Transport)
					}
					if ep.Protocol == "" || !slices.Contains(ports, ep.Port) ||
						!slices.Equal(rows[i+1], []string{a.ID, a.Address, ep.Transport, fmt.Sprint(ep.Port), ep.Protocol}) {
						t.Fatalf("endpoint/CSV disagree: %+v / %v", ep, rows[i+1])
					}
				}
				if len(planted) != 2 || planted[0].Kind != canary.KindSSHKey || planted[1].Kind != canary.KindCredential {
					t.Fatalf("unregistered archive credential or unrelated canary: %+v", planted)
				}
				netrc := baitFileAt(t, plan, "/root/.netrc")
				if netrc.Mode != 0o600 || !strings.Contains(netrc.Text, "login svc_otbackup\n") ||
					!strings.Contains(netrc.Text, "password "+planted[1].Values[0]+"\n") {
					t.Fatal("archive credential is unprotected or disagrees with canary")
				}
				if len(plan.Hosts) != 2 || plan.Hosts[0].IP == a.Address || plan.Hosts[1].IP != a.Address {
					t.Fatal("archive server and reference device must have separate addresses")
				}
				for _, f := range plan.Files {
					if strings.HasSuffix(f.Path, ".sql.gz") || strings.Contains(f.Path, "/.aws/") || strings.HasSuffix(f.Path, ".st") {
						t.Fatalf("unrelated runtime/project claim: %s", f.Path)
					}
				}
			})
		}
	}
}

func TestIndustrialBaitSettingAndCache(t *testing.T) {
	cfg := baitCfg("qp_industrialcache000000001", "debian-bookworm")
	if cowrieBaitProfile(cfg) != "ops" || effectiveSetting(cfg, "cowrie", baitProfileSetting) != "ops" {
		t.Fatal("existing ops default changed")
	}
	for _, value := range []string{"", "ops", "industrial"} {
		if err := CheckSetting("cowrie", baitProfileSetting, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckSetting("cowrie", baitProfileSetting, "plc"); err == nil {
		t.Fatal("unknown industrial file profile accepted")
	}
	ops := cowrieBaitJSON(cfg)
	var firstCanaries []byte
	seen := map[string]bool{}
	for _, device := range ConpotProfiles() {
		cfg.Honeypots["cowrie"].CustomConfig[baitProfileSetting] = "industrial"
		hp := cfg.Honeypots["conpot"]
		hp.CustomConfig = map[string]string{"template": device.ID}
		cfg.Honeypots["conpot"] = hp
		plan, planted := cowrieBait(cfg)
		fresh, _ := json.MarshalIndent(plan, "", " ")
		got := cowrieBaitJSON(cfg)
		if bytes.Equal(got, ops) || !bytes.Equal(got, append(fresh, '\n')) || seen[string(got)] {
			t.Fatalf("profile %s did not invalidate the cache", device.ID)
		}
		seen[string(got)] = true
		canariesJSON, _ := json.Marshal(planted)
		if firstCanaries == nil {
			firstCanaries = canariesJSON
		} else if !bytes.Equal(firstCanaries, canariesJSON) {
			t.Fatal("changing a reference device unnecessarily rotates the active archive credentials")
		}
	}
	for _, persona := range tpotCowriePersonas {
		cfg.Honeypots["cowrie"].CustomConfig["persona"] = persona.ID
		plan, planted := cowrieBait(cfg)
		if !persona.Server && (len(plan.Files) != 0 || len(planted) != 0) {
			t.Fatalf("industrial files on device persona %s", persona.ID)
		}
	}
	cfg.Honeypots["cowrie"].CustomConfig["persona"] = "debian-bookworm"
	cfg.Honeypots["cowrie"].CustomConfig[baitSetting] = "off"
	if plan, planted := cowrieBait(cfg); len(plan.Files) != 0 || len(planted) != 0 {
		t.Fatal("bait=off did not disable industrial files")
	}
	cfg.Honeypots["cowrie"].CustomConfig[baitSetting] = "on"
	cfg.Honeypots["cowrie"].CustomConfig[baitProfileSetting] = ""
	if !bytes.Equal(ops, cowrieBaitJSON(cfg)) {
		t.Fatal("clearing bait_profile did not restore the ops files")
	}
}

// TestBaitCacheConsistentAfterConcurrentSettingChanges reproduces a cache
// poisoning bug: separate reads formerly cached one role/device's files under
// another's key. After the writer stops, every stable selection must return
// the right files and contain the credentials PlantedCanaries watches.
func TestBaitCacheConsistentAfterConcurrentSettingChanges(t *testing.T) {
	for _, tc := range []struct {
		name, honeypot, key string
		values              []string
	}{
		{"device", "conpot", "template", []string{"plc_modbus", "beckhoff_cx"}},
		{"role", "cowrie", baitProfileSetting, []string{"ops", "industrial"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baitCfg("qp_concurrentbait0000000001", "debian-bookworm")
			cfg.SetHoneypotCustomConfig("cowrie", map[string]string{"persona": "debian-bookworm", baitProfileSetting: "industrial"})
			cfg.SetHoneypotCustomConfig("conpot", map[string]string{"template": "plc_modbus"})
			set := func(value string) {
				custom := map[string]string{tc.key: value}
				if tc.honeypot == "cowrie" {
					custom["persona"] = "debian-bookworm"
				}
				cfg.SetHoneypotCustomConfig(tc.honeypot, custom)
			}
			for attempt := 0; attempt < 40; attempt++ {
				baitCache.Lock()
				baitCache.json = nil
				baitCache.Unlock()
				stop := make(chan struct{})
				var writer sync.WaitGroup
				writer.Add(1)
				go func() {
					defer writer.Done()
					for i := 0; ; i++ {
						select {
						case <-stop:
							return
						default:
						}
						set(tc.values[i%len(tc.values)])
						runtime.Gosched()
					}
				}()
				for i := 0; i < 4; i++ {
					_ = cowrieBaitJSON(cfg)
					runtime.Gosched()
				}
				close(stop)
				writer.Wait()
				for _, value := range tc.values {
					set(value)
					var plan baitPlan
					if err := json.Unmarshal(cowrieBaitJSON(cfg), &plan); err != nil {
						t.Fatal(err)
					}
					checkBaitPlan(t, tpotCowriePersona{ID: "debian-bookworm", Server: true, Family: "debian", User: "debian"}, plan, PlantedCanaries(cfg))
					var inventory *industrialInventory
					for _, f := range plan.Files {
						if f.Path == industrialRoot+"/inventory.json" {
							if err := json.Unmarshal([]byte(f.Text), &inventory); err != nil {
								t.Fatal(err)
							}
						}
					}
					industrial := tc.honeypot != "cowrie" || value == "industrial"
					if (inventory != nil) != industrial {
						t.Fatalf("stable %s=%s returned wrong role after attempt %d", tc.key, value, attempt)
					}
					if industrial && (len(inventory.Assets) != 1 || inventory.Assets[0].Model != ConpotProfile(cfg).Model) {
						t.Fatalf("stable %s=%s returned another device's archive after attempt %d", tc.key, value, attempt)
					}
				}
			}
		})
	}
}

// TestBaitHostsTimeOut: the hosts the files name are the ones Cowrie's ssh
// treats as unreachable, under each name the files give them.
func TestBaitHostsTimeOut(t *testing.T) {
	cfg := baitCfg("qp_hosts0000000000000000000", "ubuntu-jammy")
	s := newBaitScene(cfg, serverPersonas()[1])
	plan := mustPlan(cfg)
	names := map[string]string{}
	for _, h := range plan.Hosts {
		for _, n := range h.Names {
			names[n] = h.IP
		}
	}
	for _, n := range []string{s.db.Alias, s.db.FQDN, s.db.IP} {
		if names[n] != s.db.IP {
			t.Errorf("ssh %s would not time out", n)
		}
	}
	if names[s.monitor.IP] == "" {
		t.Error("the monitor's address would not time out")
	}
}

// TestBaitMounted: the plan is mounted read-only where qpot_bait.py reads it,
// with the instance's content, and setup writes it.
func TestBaitMounted(t *testing.T) {
	cfg := baitCfg("qp_mounted00000000000000000", "rhel-9")
	var found bool
	for _, v := range deployProfile(cfg, "cowrie").Volumes {
		if v.ContainerPath == baitPlanPath {
			found = true
			if !v.File || !v.ReadOnly || string(v.Content) != string(cowrieBaitJSON(cfg)) {
				t.Fatalf("plan volume %+v", v.HostSubdir)
			}
		}
	}
	if !found {
		t.Fatal("plan not mounted")
	}
	svc, _, _ := publishedPorts(t, cfg, "cowrie")
	if !strings.Contains(svc, "/honeypots/cowrie/bait/plan.json:"+baitPlanPath+":ro\n") {
		t.Fatal("compose lacks the plan mount")
	}
}
