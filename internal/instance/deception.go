// Package instance: deception.go provides per-instance honeypot identity
// derivation to reduce fingerprintability.
//
// Research basis: the dominant weakness of a stock T-Pot deployment is that
// every instance ships globally-identical static identity strings — the same
// hostname, the same advertised SSH version, the same kernel/uname output.
// Those constants are themselves the fingerprint, and internet-scale scanners
// (Shodan Honeyscore, "Gotta Catch 'em All", and default-config probes) key on
// them. The literature's central recommendation is per-deployment randomization
// of all identity strings, kept INTERNALLY CONSISTENT (Vetterl & Clayton, USENIX
// WOOT '18; "Gotta Catch 'em All", ACM DTRAP 2023; SANS ISC diary 31064).
//
// QPot derives a deterministic-but-unique identity per instance from a stable
// seed. Deterministic so a regenerated compose keeps a stable identity; unique
// so no two QPot instances share a signature.
package instance

import (
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

// tpotCowriePersona is one persona of the Cowrie image's own persona engine.
type tpotCowriePersona struct {
	ID string
	// Server personas are full Linux servers with an OpenSSH service; the others
	// are embedded devices (routers, NAS, cameras), some with no SSH server at
	// all (Cowrie then drops every SSH connection before its banner).
	Server bool
	// Family and User are the persona's "family" and login "user" in
	// personas.json: the OS the bait files are written for and the account
	// whose home they go in (see bait.go).
	Family, User string
}

// tpotCowriePersonas are the personas of the Cowrie image at TPotVersion
// (personas/personas.json in ghcr.io/telekom-security/cowrie). Check them again
// when TPotVersion changes: an ID the image does not know stops the container.
//
// Cowrie runs as each persona through the image's start-cowrie-persona
// launcher, which renders the whole machine from it: the advertised OpenSSH
// release with that release's key exchange, host-key and server-sig-algs
// lists; uname, /proc, the process table and its start times, lscpu, lspci,
// mounts, df, the network state behind ip and ss, the packages behind dpkg/apt,
// the systemd units behind systemctl, sudo rules and per-user history settings.
// QPot's earlier approach - running twistd directly with its own cowrie.cfg and
// a patched fake filesystem - bypassed all of that, and on this image left an
// attacker with /.dockerenv, no /etc/os-release, "Exec format error" from
// mount/dmesg/lsblk, an lscpu that contradicted /proc/cpuinfo, empty package
// and unit lists and `python3 -V` printing Python 2.7.
var tpotCowriePersonas = []tpotCowriePersona{
	{"ubuntu-noble", true, "ubuntu", "ubuntu"},
	{"ubuntu-jammy", true, "ubuntu", "ubuntu"},
	{"debian-trixie", true, "debian", "debian"},
	{"debian-bookworm", true, "debian", "debian"},
	{"rhel-9", true, "rhel", "cloud-user"},
	{"centos-7", true, "centos", "centos"},
	{"raspios", true, "raspios", "pi"},
	{"gpu-ubuntu", true, "ubuntu", "ubuntu"},
	{"dlink-dir859", false, "dlink", "admin"},
	{"tplink-archer-c7", false, "tplink", "root"},
	{"zyxel-nas326", false, "zyxel", "admin"},
	{"openwrt", false, "openwrt", "root"},
	{"qnap-qts", false, "qnap", "admin"},
	{"synology-dsm", false, "synology", "admin"},
	{"ubiquiti-edgerouter-x", false, "ubiquiti", "ubnt"},
	{"ipcam", false, "ipcam", "admin"},
}

// CowriePersonaIDs returns every persona ID the Cowrie image accepts.
func CowriePersonaIDs() []string {
	ids := make([]string, len(tpotCowriePersonas))
	for i, p := range tpotCowriePersonas {
		ids[i] = p.ID
	}
	return ids
}

// cowriePersonaMaxRotation is the longest COWRIE_PERSONA_ROTATION the image
// accepts (days); the launcher refuses to start on a larger value.
const cowriePersonaMaxRotation = 365

// cowriePersonaByID returns the persona of the table with that ID.
func cowriePersonaByID(id string) (tpotCowriePersona, bool) {
	for _, p := range tpotCowriePersonas {
		if p.ID == id {
			return p, true
		}
	}
	return tpotCowriePersona{}, false
}

// cowriePersona returns the persona this instance's Cowrie presents: the
// operator's custom_config "persona" when the image knows it, otherwise one
// server persona picked from the instance seed. The seed pick is stable, so a
// restart or a regenerated compose never turns the box into a different kind
// of machine, and different instances get different personas.
func cowriePersona(cfg *config.Config) string {
	if hp, ok := cfg.GetHoneypotConfig("cowrie"); ok {
		want := strings.TrimSpace(hp.CustomConfig["persona"])
		for _, p := range tpotCowriePersonas {
			if p.ID == want {
				return want
			}
		}
	}
	var servers []string
	for _, p := range tpotCowriePersonas {
		if p.Server {
			servers = append(servers, p.ID)
		}
	}
	return servers[seededIndex("tpot-persona:"+deceptionSeed(cfg), len(servers))]
}

// cowriePersonaRotation returns COWRIE_PERSONA_ROTATION: how many days the
// launcher keeps the identity it drew (host name, OpenSSH patch level, boot
// time, addresses) across restarts. The image's own default, 0, draws a new
// identity on every start, so an attacker coming back after a restart would
// meet a different host name and uptime on the same IP. QPot keeps it for the
// longest time the image allows unless custom_config "persona_rotation" says
// otherwise.
func cowriePersonaRotation(cfg *config.Config) int {
	if hp, ok := cfg.GetHoneypotConfig("cowrie"); ok {
		if days, ok := parsePersonaRotation(hp.CustomConfig["persona_rotation"]); ok {
			return days
		}
	}
	return cowriePersonaMaxRotation
}

// parsePersonaRotation accepts what the launcher accepts: plain decimal days
// from 0 to cowriePersonaMaxRotation.
func parsePersonaRotation(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 3 || strings.Trim(v, "0123456789") != "" {
		return 0, false
	}
	days, err := strconv.Atoi(v)
	if err != nil || days > cowriePersonaMaxRotation {
		return 0, false
	}
	return days, true
}

// ConpotDeviceProfile describes an existing Conpot device, its protocols and
// container ports. The catalog lives with configuration so saved selections
// can be migrated and validated without depending on the instance runtime.
type ConpotDeviceProfile = config.ConpotDeviceProfile

type tpotConpotTemplate = ConpotDeviceProfile

// tpotConpotTemplates mirror the deployable templates of the pinned upstream
// image. The static multi-protocol "default" and "proxy" are not offered.
var tpotConpotTemplates = config.ConpotProfiles()

// ConpotProfiles returns device descriptions for CLI, API and dashboard use.
// Returned slices can be changed without changing the deployment catalog.
func ConpotProfiles() []ConpotDeviceProfile { return config.ConpotProfiles() }

// ConpotProfile returns the effective device profile for this instance.
func ConpotProfile(cfg *config.Config) ConpotDeviceProfile {
	p := conpotTemplate(cfg)
	p.Protocols = append([]string(nil), p.Protocols...)
	p.TCP = append([]int(nil), p.TCP...)
	p.UDP = append([]int(nil), p.UDP...)
	return p
}

// ConpotTemplateIDs returns every Conpot template QPot can run.
func ConpotTemplateIDs() []string {
	ids := make([]string, len(tpotConpotTemplates))
	for i, t := range tpotConpotTemplates {
		ids[i] = t.ID
	}
	return ids
}

// conpotTemplate honors the operator's pin, otherwise the persisted automatic
// choice. The fallback uses the frozen legacy catalog, never a modulo of the
// current catalog size: adding or reordering devices must not change a unit.
func conpotTemplate(cfg *config.Config) tpotConpotTemplate {
	if hp, ok := cfg.GetHoneypotConfig("conpot"); ok {
		want := strings.TrimSpace(hp.CustomConfig["template"])
		for _, t := range tpotConpotTemplates {
			if t.ID == want {
				return t
			}
		}
	}
	want := config.ConpotAutomaticProfileID(cfg)
	for _, t := range tpotConpotTemplates {
		if t.ID == want {
			return t
		}
	}
	// Parse and Save reject invalid saved IDs. A direct, unsaved config can
	// still contain one; returning an empty profile avoids impersonating a
	// different device. Such configs fail validation before deployment.
	return tpotConpotTemplate{}
}

// adbDevice is how adbd names its device in the connection banner.
type adbDevice struct {
	Name, Model, Device string
}

// adbDevices are Android 8 phones on Qualcomm chips, the kind of device the
// root listing adbhoney answers `ls` with comes from (Oreo's nonplat_*
// contexts; the bt_firmware, dsp and persist partitions). The image's own
// banner, the Galaxy S9 "starltexx", is the one every ADBHoney install sends.
var adbDevices = []adbDevice{
	{"walleye", "Pixel 2", "walleye"},
	{"taimen", "Pixel 2 XL", "taimen"},
	{"tissot", "Mi A1", "tissot_sprout"},
	{"whyred", "Redmi Note 5", "whyred"},
	{"ali", "moto g(6)", "ali"},
	{"starqltesq", "SM-G960U", "starqlte"},
	{"dreamqltesq", "SM-G950U", "dreamqlte"},
	{"greatqltesq", "SM-N950U", "greatqlte"},
	{"OnePlus5T", "ONEPLUS A5010", "OnePlus5T"},
}

// adbhoneyBanner returns the banner adbhoney sends in reply to an ADB client's
// CONNECT: one device per instance, in the form an Android 8 adbd sends it.
func adbhoneyBanner(cfg *config.Config) string {
	d := adbDevices[seededIndex("adb-device:"+deceptionSeed(cfg), len(adbDevices))]
	return "device::ro.product.name=" + d.Name + ";ro.product.model=" + d.Model +
		";ro.product.device=" + d.Device + ";features=cmd,stat_v2,shell_v2"
}

// realisticHostnames is a pool of plausible production-server hostnames. None is
// Cowrie's old default "svr04" or T-Pot's "srv01".
var realisticHostnames = []string{
	"web01", "web-prod-02", "app-server-1", "db-prod", "db01", "mail",
	"ns1", "gw-01", "vps-3", "srv-app-04", "backend-2", "edge-01",
	"node-07", "api-prod", "cache-1", "fileserver",
}

// seededIndex returns a stable index in [0,n) derived from seed. Deterministic
// (FNV-1a) so the same instance always maps to the same identity.
func seededIndex(seed string, n int) int {
	if n <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	return int(h.Sum32() % uint32(n))
}

// deceptionSeed is the per-instance seed for every attacker-visible generated
// artifact (Cowrie persona, HiFi credential persona and hostname, Conpot sensor
// id, ...).
//
// It must NOT be the QPot ID itself: that ID is the web UI/API credential, and
// the artifacts are derived with fast non-cryptographic hashes (FNV-1a) whose
// outputs an attacker can observe, giving them material to reconstruct the
// credential. A SHA-256
// derivation is one-way yet stays stable and unique per instance.
func deceptionSeed(cfg *config.Config) string {
	id := cfg.QPotID
	if id == "" {
		id = cfg.InstanceName
	}
	sum := sha256.Sum256([]byte("qpot-deception-seed-v1\x00" + id))
	return "ds_" + hex.EncodeToString(sum[:16])
}

// hostnameForSeed returns a per-instance hostname from the generic pool. This
// is the fallback when a credential persona defines no role-specific names;
// persona-driven honeypots should prefer hostnameForPersona so the name matches
// the accepted accounts.
func hostnameForSeed(seed string) string {
	return realisticHostnames[seededIndex("host:"+seed, len(realisticHostnames))]
}

// personaHostnames maps each credential persona to role-appropriate hostnames.
// When a honeypot derives its identity from a persona (the HiFi ssh-proxy
// backends), the per-instance hostname is drawn from THIS pool rather than the
// generic one, so the shell prompt, /etc/hostname and /etc/hosts match the kind
// of box the accepted credentials imply. Without this, the hostname and persona
// were chosen from independent salts, so a "voip-pbx" persona (asterisk/freepbx
// logins) could present "db-prod" - an internal contradiction a human attacker
// notices (a database server with only PBX accounts and no DB daemon). Keeping
// the two coherent is the "no persona/host mismatch" invariant credentials.go
// promises. Names avoid the known T-Pot/Cowrie defaults (srv01/svr04) and reuse
// across personas (vps-3, router) is intentional and realistic.
var personaHostnames = map[string][]string{
	"corp-ubuntu":      {"app-server-01", "appsrv-prod", "corp-app-02", "web-app-1"},
	"edge-router":      {"gw-01", "edge-fw", "border-gw", "router-01"},
	"web-hosting":      {"web01", "cpanel-host", "www-prod", "hosting-02"},
	"db-server":        {"db-prod", "db01", "postgres-01", "mysql-prod"},
	"dev-ci":           {"ci-runner-1", "jenkins-01", "build-node-2", "dev-ci"},
	"nas-storage":      {"nas-01", "storage-1", "fileshare", "synology"},
	"iot-camera":       {"ipcam-01", "camera-1", "ipc-front", "cam-lobby"},
	"mail-server":      {"mail", "mx1", "smtp-01", "mailsrv"},
	"k8s-node":         {"k8s-worker-1", "kube-node-3", "worker-02", "node-07"},
	"legacy-centos":    {"centos-app", "legacy-db", "vps-3", "oldbox-1"},
	"soho-router":      {"openwrt", "home-gw", "router", "mikrotik"},
	"voip-pbx":         {"pbx-01", "asterisk", "freepbx", "voip-gw"},
	"cctv-nvr":         {"nvr-01", "dvr-1", "cctv-rec", "nvr-back"},
	"cloud-default":    {"ip-10-0-1-23", "cloud-vm-1", "vps-3", "ec2-prod"},
	"abandoned-vps":    {"vps-3", "vm-01", "srv-app-04", "host-12"},
	"game-server":      {"ts3-server", "game-01", "mc-prod", "steam-1"},
	"jump-bastion":     {"bastion", "jump-01", "jumpbox", "bastion-prod"},
	"proxmox-host":     {"pve", "proxmox-01", "vmhost-1", "pve-node-2"},
	"gitlab-devops":    {"gitlab", "git-runner-1", "scm-prod", "ci-gitlab"},
	"monitoring-stack": {"grafana", "monitor-01", "zabbix-srv", "prometheus-1"},
	"raspberry-pi":     {"raspberrypi", "pi-01", "rpi-home", "octopi"},
	"ftp-fileserver":   {"ftp", "fileserver", "files-01", "ftp-prod"},
	"docker-host":      {"docker-01", "dockerhost", "swarm-node-1", "container-host"},
	"nextcloud":        {"nextcloud", "cloud-01", "nc-prod", "files-cloud"},
	"home-assistant":   {"homeassistant", "hass-01", "smarthome", "hassio"},
	"media-server":     {"plex-01", "mediaserver", "jellyfin", "htpc"},
	"vpn-gateway":      {"vpn-01", "vpn-gw", "wg-gateway", "openvpn"},
	"unifi-controller": {"unifi", "unifi-01", "network-ctrl", "controller"},
	"message-broker":   {"kafka-1", "broker-01", "kafka-prod", "msg-broker"},
	"wordpress-lamp":   {"wordpress", "wp-01", "blog-prod", "lamp-web"},
}

// hostnameForPersona returns a per-instance hostname coherent with the persona's
// role, drawn from that persona's own pool so the name matches the box the
// accepted credentials imply. If the persona defines no names (a new persona, or
// one deliberately left generic) it falls back to the generic pool. The same
// "host:"+seed salt as hostnameForSeed keeps the choice stable per instance.
func hostnameForPersona(t credentialTemplate, seed string) string {
	pool := personaHostnames[t.Name]
	if len(pool) == 0 {
		return hostnameForSeed(seed)
	}
	return pool[seededIndex("host:"+seed, len(pool))]
}

// conpotSiteSeedEnv is the variable Conpot's site step (site_identity.py)
// reads its site's seed from.
const conpotSiteSeedEnv = "QPOT_SITE_SEED"

// conpotSiteSeed returns the seed of this instance's Conpot site: the names,
// the DNP3 points, the OPC UA process, the tank gauge and the values the
// image would draw at random (addresses, MACs, serial numbers) all follow
// from it. It is derived from the instance's deception seed and from nothing
// else: nothing inside the container has to be saved for the site to stay the
// same, every start of the instance shows the same plant, and no two
// instances show the same one. Nothing the container writes (its state
// folder included) can change the seed or keep the instance from starting.
func conpotSiteSeed(cfg *config.Config) string {
	sum := sha256.Sum256([]byte("qpot-conpot-site-v1\x00" + deceptionSeed(cfg)))
	return hex.EncodeToString(sum[:16])
}
