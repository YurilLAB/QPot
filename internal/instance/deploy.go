package instance

// deploy.go describes the per-honeypot container runtime requirements.
//
// Each upstream honeypot image expects specific mount points, tmpfs, and ports
// — a single generic "/var/log/honeypot + /data" mount (the previous behavior)
// does not work for any of them, so honeypots either failed to start or wrote
// their logs to a path the collector never reads. These profiles are derived
// from T-Pot's reference compose files (vendored under docker/<name>/) and the
// cowrie/endlessh profiles are verified by actually running the images.

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

// deployVolume maps a host path (under {DataPath}/honeypots/<name>) to a path
// inside the honeypot container.
type deployVolume struct {
	HostSubdir    string
	ContainerPath string
	// File indicates HostSubdir is a single file (e.g. a generated config),
	// not a directory — so setup creates its parent dir and writes the file,
	// rather than creating a directory at that path.
	File bool
	// ReadOnly mounts it read-only. The host writes it; the container must
	// not be able to change it.
	ReadOnly bool
	// Content is what setup writes to a File volume before start.
	Content []byte
}

// heraldingConfig is the /etc/heralding/heralding.yml of
// ghcr.io/telekom-security/heralding at TPotVersion with the values that
// override heralding's persona cleared: the banners and FTP system type of
// ftp, pop3(s), imap(s), ssh and smtp(s), and the certificate country. The
// image's file kept stock greetings that every install shared and that
// contradicted the persona on the other ports (an RHEL persona answering SSH
// as OpenSSH 6.6.1p1 on Ubuntu 14.04, FTP as "Microsoft FTP Server" and SMTP
// as Exchange). Empty values come from the persona. The rest of the file is
// the image's; compare it again when TPotVersion changes.
//
//go:embed honeypotfiles/heralding.yml
var heraldingConfig []byte

// cowriePatchVersion is the TPotVersion whose cowrie image the files below
// were made from; a test fails when TPotVersion moves, so they are compared
// again before they are mounted over a different image.
const cowriePatchVersion = "24.04.2"

// The cowrie patch layer: files of ghcr.io/telekom-security/cowrie at
// cowriePatchVersion with QPot's changes, mounted read-only over the image's
// own (the image's .pyc files are timestamp-checked, so Python compiles the
// mounted source). Each change is marked "QPot:" in the file. The image's
// originals were (sha256):
//
//	shell/protocol.py      c96e9155ac0133572a746fbbd9599acdd66d8100996f4811221e46174f41c6be
//	commands/ping.py       4465c53089915a5085a5c4d0a5de5577e7e8c1de2dcf730c9fa53932b021cd2b
//	commands/__init__.py   74da6fe7d2fa304bfab8594a21056ed94905db4bade7a80602697d35df52d68e
//	commands/ssh.py        4844fe51fa5288818bdcce1d1f730ebf92c4e21ffddb6b432e36797b863e1ae5
//	core/honeyfs.py        589d5dedf1473a0db69f443c53c836e711343e5bb6e30fd63033caa99cc53fc0
//	commands/find.py       4f098f1066f471698f82f34380cf349706e416aa2219c935af185328dbb5420f
//	shell/bashparse.py     f0fd17031828d3c98725cd461cc16986879c4bff7c632d8f76d36d2d6daba6e9
//	commands/curl.py       d4e53f5bfc75eee50a3c69a6ca9998fa41631276ff373353dcacd8ff4d709417
//	commands/wget.py       1fec4c13975c5827fe557a73fd547f27302af0e959ea1adfd7f1e1afe31191c1
//
// protocol.py: the line editor writes what bash's readline (or BusyBox's ash
// on the firmware personas) writes, as recorded from bash 5.2.37 and BusyBox
// 1.37.0: no terminal insert mode (ESC[4h before every prompt), bracketed
// paste on bash 5.1 and later, ^C at the prompt, readline's cursor and erase
// sequences. ping.py: iputils of the persona's release or BusyBox's ping,
// where Cowrie's rejected `ping -c 4 host`. coreutils.py (new, loaded last
// through commands/__init__.py): hostname (`hostname -f` renamed the host to
// "-f"), bash --version, logout at the login shell, and programs every
// persona has that ended in "Exec format error": arch, timeout, setsid, nice,
// basename, dirname, md5sum and the sha sums, mktemp, tty, sync, printenv,
// expr.
//
// The bait files (bait.go): core/qpot_bait.py (new) adds the plan to the
// persona's tree, called by honeyfs.py when it loads the tree; protocol.py
// reads the history file at login, as bash does, so `history` shows what
// ~/.bash_history holds; ssh.py times out on the internal hosts the files name
// and logs what is typed at its prompts and the keys it would offer; awscli.py
// (new) answers the AWS CLI the bait installs. find.py: the image's find
// followed every link to a directory, so `find / -name id_rsa` (the first
// thing a credential harvester runs) held the reactor for many minutes; it
// now walks as GNU find -P does, bounded. bashparse.py: pathname expansion,
// which the image left to each command and almost none did, so `cat
// /etc/cron.d/*` answered "No such file or directory" for listed files.
//
// curl.py and wget.py: curl's and GNU wget's options, exit codes and messages
// as the persona's release has them (recorded from curl 8.14.1 and wget
// 1.25.0, the older releases' from their sources), where Cowrie's took six of
// curl's options and said "Could not resolve host" for an address. A refused
// address is refused, an internal or private one times out as the kernel
// gives up, and nothing reaches the network that did not before: one name
// lookup (none for a name of /etc/hosts), one GET or HEAD, no redirect
// followed, retries simulated. Every connection goes to the address that was
// checked (coreutils.py's qpot_fetch, and FTP's control and data connections),
// never to a second lookup of the name: upstream's fetch looked the name up
// again, and Twisted's FTP client connected to any host a PASV answer named.
//
// ssh.py: scp and sftp of OpenSSH's client (Cowrie had only scp's server
// side): their options and config read as ssh reads them, the key they would
// offer logged as ssh's is, and OpenSSH's messages and exit statuses for a
// host that times out, refuses or asks for a password (recorded from OpenSSH
// 10.0p2, the older releases' from their sources).
var (
	//go:embed honeypotfiles/cowrie/protocol.py
	cowrieProtocolPy []byte
	//go:embed honeypotfiles/cowrie/ping.py
	cowriePingPy []byte
	//go:embed honeypotfiles/cowrie/coreutils.py
	cowrieCoreutilsPy []byte
	//go:embed honeypotfiles/cowrie/commands_init.py
	cowrieCommandsInitPy []byte
	//go:embed honeypotfiles/cowrie/ssh.py
	cowrieSSHPy []byte
	//go:embed honeypotfiles/cowrie/awscli.py
	cowrieAWSCLIPy []byte
	//go:embed honeypotfiles/cowrie/honeyfs.py
	cowrieHoneyfsPy []byte
	//go:embed honeypotfiles/cowrie/qpot_bait.py
	cowrieQPotBaitPy []byte
	//go:embed honeypotfiles/cowrie/find.py
	cowrieFindPy []byte
	//go:embed honeypotfiles/cowrie/bashparse.py
	cowrieBashparsePy []byte
	//go:embed honeypotfiles/cowrie/curl.py
	cowrieCurlPy []byte
	//go:embed honeypotfiles/cowrie/wget.py
	cowrieWgetPy []byte
)

// cowrieSource is where the image keeps Cowrie's Python package.
const cowrieSource = "/home/cowrie/cowrie/src/cowrie"

// cowriePatchVolumes mounts the patch layer read-only over the image's files.
func cowriePatchVolumes() []deployVolume {
	file := func(name, target string, content []byte) deployVolume {
		return deployVolume{HostSubdir: "patch/" + name, ContainerPath: cowrieSource + "/" + target,
			File: true, ReadOnly: true, Content: content}
	}
	return []deployVolume{
		file("protocol.py", "shell/protocol.py", cowrieProtocolPy),
		file("ping.py", "commands/ping.py", cowriePingPy),
		file("coreutils.py", "commands/coreutils.py", cowrieCoreutilsPy),
		file("commands_init.py", "commands/__init__.py", cowrieCommandsInitPy),
		file("ssh.py", "commands/ssh.py", cowrieSSHPy),
		file("awscli.py", "commands/awscli.py", cowrieAWSCLIPy),
		file("honeyfs.py", "core/honeyfs.py", cowrieHoneyfsPy),
		file("qpot_bait.py", "core/qpot_bait.py", cowrieQPotBaitPy),
		file("find.py", "commands/find.py", cowrieFindPy),
		file("bashparse.py", "shell/bashparse.py", cowrieBashparsePy),
		file("curl.py", "commands/curl.py", cowrieCurlPy),
		file("wget.py", "commands/wget.py", cowrieWgetPy),
	}
}

// adbhoneyConfig is the adbhoney.cfg of ghcr.io/telekom-security/adbhoney at
// TPotVersion with two changes. device_id, the banner every ADB client gets,
// was "device::http://ro.product.name =starltexx;...", whose stray "http://"
// and space mark ADBHoney on every install; it is now a well-formed banner of
// a device picked per instance (adbhoneyBanner). http_download is off: the
// image's downloader fetches any URL an attacker types, from the honeypot's
// own network (upstream fixed that SSRF in t3chn0m4g3/ADBHoney 6f2ac93, after
// the commit the image is built from). Files pushed with `adb push` are kept.
func adbhoneyConfig(cfg *config.Config) []byte {
	return []byte(`[honeypot]
hostname = honeypot01

address = 0.0.0.0
port = 5555
http_download = false
http_timeout = 45

download_dir = dl/
log_dir = log/

device_id = ` + adbhoneyBanner(cfg) + `

[output_log]
enabled = true
log_file = adbhoney.log
log_level = info

[output_json]
enabled = true
log_file = adbhoney.json
`)
}

// honeypotDeploy is the deployment profile for one honeypot image.
type honeypotDeploy struct {
	// Tmpfs are raw docker-compose tmpfs entries the image needs (e.g. cowrie
	// requires a writable /tmp/cowrie for its pidfile and state).
	Tmpfs []string
	// Volumes are host-subdir -> container-path mounts. The "logs" subdir, when
	// present, is the directory the collector (Vector) reads
	// ({DataPath}/honeypots/<name>/logs), so each honeypot's log path must mount
	// from that subdir.
	Volumes []deployVolume
	// Ports are the TCP container ports to publish. Each is given a
	// deterministic host port via Config.AllocatePortFor. Empty means "use the
	// honeypot's configured HP.Port" (generic fallback).
	Ports []int
	// UDPPorts are the UDP container ports to publish (e.g. ddospot, conpot
	// SNMP/BACnet). Rendered with a /udp suffix.
	UDPPorts []int
	// Env are image-specific environment variables the honeypot's entrypoint
	// requires (e.g. conpot's CONPOT_* args). Keys are sorted for deterministic
	// output.
	Env map[string]string
	// ExtraCaps are Linux capabilities to ADD back to the cap_drop=ALL bounding
	// set, beyond the default SETUID/SETGID (+ NET_BIND_SERVICE for privileged
	// ports). Needed when an image's entrypoint binary carries FILE capabilities:
	// the kernel refuses to execve a file whose permitted file-caps are not in the
	// process bounding set (EPERM), even if the program never uses them. E.g.
	// log4pot's /usr/bin/python3 has cap_net_bind_service=ep but binds only 8080,
	// so without NET_BIND_SERVICE in the bounding set the interpreter cannot start.
	ExtraCaps []string
	// NoShell marks images without /bin/sh (static Go binaries on scratch /
	// distroless). The /proc/net healthcheck runs through a shell, so it can
	// never succeed there; such honeypots get no in-container healthcheck and
	// `qpot setup`/`doctor` probe their published TCP ports from the host.
	NoShell bool
	// HealthPorts are the container ports the healthcheck probes when they
	// differ from the published ones (e.g. tanner's server, whose web front end
	// is the snare companion).
	HealthPorts []int
	// Internal means the service publishes no host port itself (tanner: the
	// attacker-facing port is published by its snare companion).
	Internal bool
	// RunAsUID is the image's non-root user ("uid:gid"). Mounted directories
	// listed in OwnedSubdirs are handed to it before start, for images that
	// chmod their own log dir (only the owner may; capabilities do not apply
	// to a non-root process).
	RunAsUID     string
	OwnedSubdirs []string
	// LLMEnv maps honeypot custom_config keys to the container environment
	// variables of an LLM-backed honeypot; LLMRequired are the keys that must
	// be set (the image refuses to start without a provider).
	LLMEnv      map[string]string
	LLMRequired []string
	// Settings are the other custom_config keys the honeypot reads (set with
	// `qpot honeypot set`), e.g. cowrie's persona or ssh-proxy's backends.
	Settings []string
	// Values restricts settings to the values the image accepts.
	Values map[string][]string
}

// NeedsNetBind reports whether the honeypot binds a privileged port (<1024)
// INSIDE the container. Such images (e.g. cowrie on 22/23) need
// CAP_NET_BIND_SERVICE in the capability bounding set; without it, exec of a
// binary carrying file capabilities fails with EPERM under cap_drop=ALL. This
// is keyed on the container-internal ports, not the host-facing HP.Port.
func (d honeypotDeploy) NeedsNetBind() bool {
	for _, p := range append(append([]int{}, d.Ports...), d.UDPPorts...) {
		if p > 0 && p < 1024 {
			return true
		}
	}
	return false
}

// deployProfile returns the deployment profile of a honeypot in this instance:
// deployProfileFor plus the parts that depend on the configuration. Conpot
// runs the template conpotTemplate picks and publishes exactly the ports that
// template listens on, no more: a published port with nothing behind it
// accepts the connection and drops it, which no real device does. Adbhoney's
// config carries the instance's device banner.
func deployProfile(cfg *config.Config, name string) honeypotDeploy {
	d := deployProfileFor(name)
	if cfg == nil {
		return d
	}
	switch name {
	case "conpot":
		t := conpotTemplate(cfg)
		d.Ports = slices.Clone(t.TCP)
		d.UDPPorts = slices.Clone(t.UDP)
		d.Env = maps.Clone(d.Env)
		d.Env["CONPOT_TEMPLATE"] = t.ID
	case "adbhoney":
		d.Volumes = slices.Clone(d.Volumes)
		for i, v := range d.Volumes {
			if v.HostSubdir == "adbhoney.cfg" {
				d.Volumes[i].Content = adbhoneyConfig(cfg)
			}
		}
	case "cowrie":
		d.Volumes = slices.Clone(d.Volumes)
		for i, v := range d.Volumes {
			if v.ContainerPath == baitPlanPath {
				d.Volumes[i].Content = cowrieBaitJSON(cfg)
			}
		}
	case "dionaea":
		named := map[string][]byte{}
		for _, v := range dionaeaPatchVolumes(cfg) {
			named[v.ContainerPath] = v.Content
		}
		d.Volumes = slices.Clone(d.Volumes)
		for i, v := range d.Volumes {
			if content, ok := named[v.ContainerPath]; ok {
				d.Volumes[i].Content = content
			}
		}
	}
	return d
}

// deployPorts returns the container ports (TCP, UDP) deployProfile gives the
// honeypot, without building the files it mounts: the host port map asks for
// every honeypot's ports many times per render, and Cowrie's bait plan takes
// milliseconds to draw.
func deployPorts(cfg *config.Config, name string) (tcp, udp []int) {
	if cfg != nil && name == "conpot" {
		t := conpotTemplate(cfg)
		return slices.Clone(t.TCP), slices.Clone(t.UDP)
	}
	d := deployProfileFor(name)
	return d.Ports, d.UDPPorts
}

// Dionaea's machine name. Every T-Pot install answered as the same machine:
// SMB named it ADFS in the domain DACH (services/smb.yaml), while the LSA and
// SAMR calls (smb/rpcservices.py) and the MSSQL login reply
// (mssql/include/tds.py) still said dionaea's own default, HOMEUSER-3AF6FE, so
// one box gave two names. Each instance now answers everywhere with one name of
// its own, in the workgroup a standalone Windows 7 joins by default. The image's
// files are mounted read-only with that name in place of the old ones (the
// image's .pyc files are timestamp-checked, so Python compiles the mounted
// source); nothing else in them changes. Dionaea is GPL-2.0-or-later. The
// image's originals were (sha256):
//
//	etc/dionaea/services/smb.yaml   918009dbab404b00d0bab8ab4d338b986d963e2f1188557ff431a57e8942188a
//	smb/rpcservices.py              40d3000b53d41db87539b12fdfaf54b87553d45627dafe4ec9f7e42730c8b4c7
//	smb/include/smbfields.py        926f5f850d9d527e775e8d4bb3917e72c4e5618bc67b5846bf7bd9dec51f8c5d
//	smb/extras.py                   839f8205009acd69857060623bdb7ed53c3d8f5e1d7fb1d97a52e7686e0883b3
//	mssql/include/tds.py            7e72a4b5d0dd4d54d71b62331a829c0bf9be317ea9692bcc5d3a2f77fbdf7546
var (
	//go:embed honeypotfiles/dionaea/smb.yaml
	dionaeaSMBYaml []byte
	//go:embed honeypotfiles/dionaea/rpcservices.py
	dionaeaRPCServicesPy []byte
	//go:embed honeypotfiles/dionaea/smbfields.py
	dionaeaSMBFieldsPy []byte
	//go:embed honeypotfiles/dionaea/extras.py
	dionaeaExtrasPy []byte
	//go:embed honeypotfiles/dionaea/tds.py
	dionaeaTDSPy []byte
)

// dionaeaStockName is dionaea's own default name, hard-coded in its Python.
const dionaeaStockName = "HOMEUSER-3AF6FE"

// dionaeaWorkgroup is the workgroup of a Windows 7 machine that joined none.
const dionaeaWorkgroup = "WORKGROUP"

// dionaeaSMBStock are the lines of the image's smb.yaml that named every
// install's machine, and the setting each one holds.
var dionaeaSMBStock = [][2]string{
	{"    primary_domain: DACH\n", "primary_domain"},
	{"    oem_domain_name: DACH\n", "oem_domain_name"},
	{"    server_name: ADFS\n", "server_name"},
}

// dionaeaSource and dionaeaEtc are where the image keeps dionaea's Python
// package and its configuration.
const (
	dionaeaSource = "/opt/dionaea/lib/dionaea/python/dionaea"
	dionaeaEtc    = "/opt/dionaea/etc/dionaea"
)

// dionaeaUsers are the names Windows 7 setup makes a computer name of
// (<USER>-PC); a machine set up from an image is named WIN- and 11 random
// characters instead.
var dionaeaUsers = []string{"ADMIN", "USER", "OWNER", "OFFICE", "RECEPTION", "ACCOUNTS", "SALES",
	"FRONTDESK", "MANAGER", "STUDIO", "LAB", "SHOP", "WORKSHOP", "PAYROLL"}

// dionaeaName is the instance's machine name: stable for the instance and at
// most 15 characters (a NetBIOS name).
func dionaeaName(cfg *config.Config) string {
	seed := deceptionSeed(cfg)
	sum := sha256.Sum256([]byte("dionaea-name:" + seed))
	if sum[0]%5 < 2 {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		var b strings.Builder
		b.WriteString("WIN-")
		for _, c := range sum[1:12] {
			b.WriteByte(alphabet[int(c)%len(alphabet)])
		}
		return b.String()
	}
	return dionaeaUsers[seededIndex("dionaea-user:"+seed, len(dionaeaUsers))] + "-PC"
}

// dionaeaSMBConfig is the image's smb.yaml with the instance's name and
// workgroup.
func dionaeaSMBConfig(cfg *config.Config) []byte {
	out := dionaeaSMBYaml
	values := map[string]string{"primary_domain": dionaeaWorkgroup, "oem_domain_name": dionaeaWorkgroup,
		"server_name": dionaeaName(cfg)}
	for _, line := range dionaeaSMBStock {
		out = bytes.Replace(out, []byte(line[0]), []byte("    "+line[1]+": "+values[line[1]]+"\n"), 1)
	}
	return out
}

// dionaeaPatchVolumes mounts the name-bearing files with cfg's name; with a nil
// cfg the volumes carry no content (deployProfile fills it in).
func dionaeaPatchVolumes(cfg *config.Config) []deployVolume {
	files := []struct {
		name, target string
		original     []byte
	}{
		{"smb.yaml", dionaeaEtc + "/services/smb.yaml", dionaeaSMBYaml},
		{"rpcservices.py", dionaeaSource + "/smb/rpcservices.py", dionaeaRPCServicesPy},
		{"smbfields.py", dionaeaSource + "/smb/include/smbfields.py", dionaeaSMBFieldsPy},
		{"extras.py", dionaeaSource + "/smb/extras.py", dionaeaExtrasPy},
		{"tds.py", dionaeaSource + "/mssql/include/tds.py", dionaeaTDSPy},
	}
	out := make([]deployVolume, 0, len(files))
	for _, f := range files {
		v := deployVolume{HostSubdir: "patch/" + f.name, ContainerPath: f.target, File: true, ReadOnly: true}
		if cfg != nil {
			if f.name == "smb.yaml" {
				v.Content = dionaeaSMBConfig(cfg)
			} else {
				v.Content = bytes.ReplaceAll(f.original, []byte(dionaeaStockName), []byte(dionaeaName(cfg)))
			}
		}
		out = append(out, v)
	}
	return out
}

// deployProfileFor returns the configuration-independent deployment profile
// for a honeypot by name; use deployProfile for what an instance runs.
// Unknown honeypots get a generic profile (legacy behavior) so they are not
// broken further, but the verified images (cowrie, endlessh) get correct specs.
func deployProfileFor(name string) honeypotDeploy {
	switch name {
	case "cowrie":
		// The image's own launcher (start-cowrie-persona) renders Cowrie as the
		// persona in COWRIE_PERSONA (see deception.go and the compose template)
		// into the tmpfs /tmp/cowrie/runtime and runs twistd from there. It
		// needs: a writable etc (the persona's SSH host keys in etc/<persona>/
		// and persona-state.json, which keeps the drawn identity across
		// restarts), the log and download dirs, and tmpfs /tmp/cowrie plus
		// /tmp/cowrie/data for the rendered runtime, pidfile and state. It
		// listens on 22 (SSH) and 23 (telnet). Verified by running
		// ghcr.io/telekom-security/cowrie:24.04.2 this way and logging in.
		return honeypotDeploy{
			Tmpfs: []string{
				"/tmp/cowrie:uid=2000,gid=2000",
				"/tmp/cowrie/data:uid=2000,gid=2000",
			},
			Volumes: append([]deployVolume{
				{HostSubdir: "etc", ContainerPath: "/home/cowrie/cowrie/etc"},
				{HostSubdir: "logs", ContainerPath: "/home/cowrie/cowrie/log"},
				{HostSubdir: "dl", ContainerPath: "/home/cowrie/cowrie/dl"},
				// The bait files and canaries of the persona (bait.go), added to
				// its tree by the patch layer's qpot_bait.py; the content depends
				// on the instance (deployProfile).
				{HostSubdir: "bait/plan.json", ContainerPath: baitPlanPath, File: true, ReadOnly: true},
			}, cowriePatchVolumes()...),
			Ports:    []int{22, 23},
			Settings: []string{"persona", "persona_rotation", baitSetting},
			Values:   map[string][]string{"persona": CowriePersonaIDs(), baitSetting: {"on", "off"}},
		}
	case "endlessh":
		// Verified: endlessh redirects its log to /var/log/endlessh and listens
		// on 2222 inside the container (T-Pot maps host 22 -> 2222).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/endlessh"},
			},
			Ports: []int{2222},
		}
	case "ssh-proxy":
		// HiFi broker (cmd/qpot-sshproxy): a transparent L4 splice listening on
		// 2222 (>1024, so no NET_BIND_SERVICE needed) and writing its NDJSON
		// session log under logs/, which the collector ingests. The broker needs
		// no generated config (it is env-configured) and no other mounts; the
		// real-OpenSSH backends are rendered as companion services (sshproxy.go).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/ssh-proxy"},
				// Backend recreation counters, written by the host recycler
				// (instance.BackendRecycler) and read by the broker's
				// proxy.GenerationGate.
				{HostSubdir: "generations", ContainerPath: sshProxyGenerationsPath, ReadOnly: true},
			},
			Ports:    []int{2222},
			Settings: []string{"backends"},
		}
	case "redishoneypot":
		// Redis honeypot: single TCP port 6379, logs to /var/log/redishoneypot.
		// Derived from docker/redishoneypot/docker-compose.yml.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/redishoneypot"},
			},
			Ports: []int{6379},
		}
	case "adbhoney":
		// Android Debug Bridge honeypot: port 5555, logs to /opt/adbhoney/log.
		// It saves files pushed with `adb push` to dl/ under its working dir;
		// on the read-only root that write failed, so every push broke off
		// mid-transfer and nothing was kept. The config it reads from
		// _internal/ is QPot's, filled in by deployProfile (adbhoneyConfig).
		// Verified by running ghcr.io/telekom-security/adbhoney:24.04.2 this
		// way and pushing a file to it.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/adbhoney/log"},
				{HostSubdir: "dl", ContainerPath: "/opt/adbhoney/dl"},
				{HostSubdir: "adbhoney.cfg", ContainerPath: "/opt/adbhoney/_internal/adbhoney.cfg", File: true, ReadOnly: true},
			},
			Ports: []int{5555},
		}

	// The profiles below are derived from T-Pot's tested reference composes
	// (docker/<name>/docker-compose.yml): the in-container log path, the ports
	// each honeypot listens on, and any required tmpfs.
	case "dionaea":
		// SMB, DCE/RPC and MSSQL name the machine; the files that hold its name
		// are mounted with the instance's own (dionaeaPatchVolumes, content from
		// deployProfile).
		return honeypotDeploy{
			Volumes: append([]deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/dionaea/var/log"}},
				dionaeaPatchVolumes(nil)...),
			Ports:    []int{20, 21, 42, 81, 135, 443, 445, 1433, 1723, 1883, 3306, 5060, 5061, 27017},
			UDPPorts: []int{69, 5060},
		}
	case "conpot":
		// The image's CMD (tpot_templates.py render "$CONPOT_TEMPLATE") renders
		// the template into CONPOT_TMP with the device identity it keeps in
		// /var/lib/conpot, then starts conpot with the other CONPOT_* paths.
		// Without a writable /var/lib/conpot it draws a new identity (address,
		// MAC, serials) on every start. The template and its ports depend on
		// the instance: deployProfile fills them in (see conpotTemplate).
		// Verified by running ghcr.io/telekom-security/conpot:24.04.2 this way
		// with each template.
		return honeypotDeploy{
			Tmpfs: []string{"/tmp/conpot:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/conpot"},
				{HostSubdir: "state", ContainerPath: "/var/lib/conpot"},
			},
			Env: map[string]string{
				"CONPOT_TMP":      "/tmp/conpot",
				"CONPOT_CONFIG":   "/etc/conpot/conpot.cfg",
				"CONPOT_LOG":      "/var/log/conpot/conpot.log",
				"CONPOT_JSON_LOG": "/var/log/conpot/conpot.json",
			},
			Settings: []string{"template"},
			Values:   map[string][]string{"template": ConpotTemplateIDs()},
		}
	case "heralding":
		// Heralding draws a persona (host name, OS, banners, certificate
		// subject) on first start and keeps it, with the TLS certificates and
		// SSH host keys made for it, in its working directory /tmp/heralding.
		// On a tmpfs, as T-Pot mounts it, every restart turned the box into a
		// different machine with new host keys, so the directory is a
		// persistent volume. The config is QPot's (see heraldingConfig).
		// Verified by running ghcr.io/telekom-security/heralding:24.04.2 this
		// way: same persona, banners and certificate after a restart.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/heralding"},
				{HostSubdir: "state", ContainerPath: "/tmp/heralding"},
				{HostSubdir: "heralding.yml", ContainerPath: "/etc/heralding/heralding.yml", File: true, ReadOnly: true, Content: heraldingConfig},
			},
			Ports: []int{21, 22, 23, 25, 80, 110, 143, 443, 465, 993, 995, 1080, 3306, 3389, 5432, 5900},
		}
	case "mailoney":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/mailoney/logs"}},
			Ports:   []int{25},
		}
	case "ddospot":
		// ddospot v2 (T-Pot 24.04.2) is a static Go rewrite: CHARGEN 19/udp,
		// DNS 53/udp+tcp, NTP 123/udp, SSDP 1900/udp (SNMP 161 is gone, as in
		// T-Pot). It logs JSON lines to DDOSPOT_LOG_DIR (default
		// /var/log/ddospot); the v1 mount at /opt/ddospot/ddospot/logs - still
		// in T-Pot's own compose - leaves it writing to the read-only root, so
		// every log line is lost ("log write errors").
		return honeypotDeploy{
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/ddospot"}},
			Env:      map[string]string{"DDOSPOT_LOG_DIR": "/var/log/ddospot"},
			Ports:    []int{53},
			UDPPorts: []int{19, 53, 123, 1900},
			NoShell:  true,
		}
	case "ciscoasa":
		// 24.04.2 is a static Go rewrite (asapot) that keeps its device
		// identity (identity.json) and captured payloads in /var/lib/ciscoasa;
		// under a read-only root it exits with "mkdir /var/lib: read-only file
		// system" - also with T-Pot's own compose. A persistent state dir keeps
		// the identity stable across restarts.
		return honeypotDeploy{
			Tmpfs: []string{"/tmp/ciscoasa:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/ciscoasa"},
				{HostSubdir: "state", ContainerPath: "/var/lib/ciscoasa"},
			},
			Ports:    []int{8443},
			UDPPorts: []int{5000},
			NoShell:  true,
		}
	case "citrixhoneypot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/citrixhoneypot/logs"}},
			Ports:   []int{443},
		}
	case "elasticpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/elasticpot/log"}},
			Ports:   []int{9200},
		}
	case "ipphoney":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/ipphoney/log"}},
			Ports:   []int{631},
		}
	case "medpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/medpot"}},
			Ports:   []int{2575},
			NoShell: true,
		}
	case "dicompot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/dicompot"}},
			Ports:   []int{11112},
			NoShell: true,
		}
	case "honeyaml":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/honeyaml/log"}},
			Ports:   []int{8080},
			NoShell: true,
		}
	case "tanner":
		// Web application honeypot, run as T-Pot runs it: this service is the
		// tanner analysis server (internal, :8090); the attacker-facing web
		// front end is the snare companion, which publishes tanner's port, and
		// tanner_api / tanner_phpox / tanner_redis complete the stack on the
		// egress-blocked tanner_backend network (see tannerStack in compose.go).
		// T-Pot did not rebuild these images for 24.04.2 (tpotPinned).
		return honeypotDeploy{
			Tmpfs: []string{"/tmp/tanner:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/tanner"},
				{HostSubdir: "files", ContainerPath: "/opt/tanner/files"},
			},
			Ports:       []int{80}, // allocated for tanner, published by snare
			Internal:    true,
			HealthPorts: []int{8090},
		}
	case "beelzebub":
		// LLM-backed SSH/HTTP/TCP. Its SSH, HTTP and PostgreSQL services fail
		// validation without an LLM, so custom_config must set llm_provider
		// (ollama or openai), llm_model and, for Ollama or an
		// OpenAI-compatible server, llm_host; `qpot honeypot enable` checks.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/beelzebub/configurations/log"},
				{HostSubdir: "key", ContainerPath: "/opt/beelzebub/configurations/key"},
			},
			Ports:   []int{22, 80, 2222, 3306, 8080},
			NoShell: true,
			LLMEnv: map[string]string{
				"llm_provider": "LLM_PROVIDER",
				"llm_model":    "LLM_MODEL",
				"llm_host":     "LLM_HOST",
			},
			LLMRequired: []string{"llm_provider", "llm_model"},
			Values:      map[string][]string{"llm_provider": {"ollama", "openai"}},
		}
	case "galah":
		// LLM-backed dynamic web honeypot; exits without a provider, so
		// custom_config must set llm_provider (and llm_server_url + llm_model
		// for Ollama, or llm_api_key for a hosted model).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/galah/log"},
				{HostSubdir: "cache", ContainerPath: "/opt/galah/config/cache"},
			},
			Ports: []int{80, 443, 8080, 8443},
			LLMEnv: map[string]string{
				"llm_provider":       "LLM_PROVIDER",
				"llm_server_url":     "LLM_SERVER_URL",
				"llm_model":          "LLM_MODEL",
				"llm_temperature":    "LLM_TEMPERATURE",
				"llm_api_key":        "LLM_API_KEY",
				"llm_cloud_location": "LLM_CLOUD_LOCATION",
				"llm_cloud_project":  "LLM_CLOUD_PROJECT",
			},
			LLMRequired: []string{"llm_provider", "llm_model"},
		}
	case "go-pot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/go-pot/log"}},
			Ports:   []int{8080},
			NoShell: true,
		}
	case "h0neytr4p":
		// Needs a writable payloads dir; the read-only root otherwise blocks
		// its `mkdir /data`. It runs as 2000:2000 and chmods its log dir at
		// start, which only the owner may do, so QPot hands that dir to it
		// (T-Pot's tpotinit does the same for its data dirs).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/h0neytr4p/log"},
				{HostSubdir: "payloads", ContainerPath: "/data/h0neytr4p/payloads"},
			},
			Ports:        []int{80, 443},
			NoShell:      true,
			RunAsUID:     "2000:2000",
			OwnedSubdirs: []string{"logs", "payloads"},
		}
	case "hellpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/hellpot"}},
			Ports:   []int{8080},
			NoShell: true,
		}
	case "log4pot":
		// log4pot writes captured payloads to /var/log/log4pot/payloads via
		// os.mkdir at startup; with a read-only root that directory must be a
		// writable mount or the server crashes before binding. Mirror T-Pot's
		// reference compose (log + payloads).
		return honeypotDeploy{
			Tmpfs: []string{"/tmp:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/log4pot/log"},
				{HostSubdir: "payloads", ContainerPath: "/var/log/log4pot/payloads"},
			},
			Ports: []int{8080},
			// The image's /usr/bin/python3 carries cap_net_bind_service=ep; under
			// cap_drop=ALL the kernel won't exec it ("operation not permitted")
			// unless the cap is in the bounding set, even though log4pot binds 8080.
			ExtraCaps: []string{"NET_BIND_SERVICE"},
		}
	case "miniprint":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/miniprint/log"}},
			Ports:   []int{9100},
		}
	case "sentrypeer":
		return honeypotDeploy{
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/sentrypeer"}},
			UDPPorts: []int{4222, 5060},
		}
	case "wordpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/wordpot/logs"}},
			Ports:   []int{80},
		}

	default:
		// Generic fallback for honeypots without a verified profile.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/honeypot"},
				{HostSubdir: "data", ContainerPath: "/data"},
			},
		}
	}
}

// MissingLLMConfig returns the custom_config keys an LLM-backed honeypot
// still needs (nil when it needs none or all are set).
func MissingLLMConfig(name string, custom map[string]string) []string {
	var missing []string
	for _, k := range deployProfileFor(name).LLMRequired {
		if strings.TrimSpace(custom[k]) == "" {
			missing = append(missing, k)
		}
	}
	return missing
}

// CheckSetting reports whether value is accepted for the honeypot's setting
// key (an empty value, which removes the setting, always is).
func CheckSetting(name, key, value string) error {
	if value == "" {
		return nil
	}
	if name == "cowrie" && key == "persona_rotation" {
		if _, ok := parsePersonaRotation(value); !ok {
			return fmt.Errorf("%s: %s must be a number of days from 0 to %d", name, key, cowriePersonaMaxRotation)
		}
		return nil
	}
	allowed := deployProfileFor(name).Values[key]
	if len(allowed) == 0 || slices.Contains(allowed, value) {
		return nil
	}
	return fmt.Errorf("%s: %s must be one of: %s", name, key, strings.Join(allowed, ", "))
}
