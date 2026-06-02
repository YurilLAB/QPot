package instance

import (
	"fmt"
	"strings"
)

// honeyfs.go generates a per-instance fake-filesystem layer for Cowrie so that
// post-login recon is internally consistent with the login persona and the
// advertised system identity.
//
// Research basis (Cowrie HONEYFS docs; Cowrie #1102 "/home/richard" tell;
// "Gotta Catch 'em All" DTRAP 2023; cryptax "Customizing Cowrie"): the dominant
// remaining Cowrie tell after identity/credential randomization is INTERNAL
// INCONSISTENCY — an attacker logs in as a persona user (e.g. jmartin), runs
// `cat /etc/passwd`, and that user is absent. Stock Cowrie also ships no
// /etc/os-release and a generic /etc/passwd/issue/hostname identical on every
// deployment. We generate these honeyfs files from the SAME persona + distro
// seed used for the credentials and the SSH identity, then bind-mount them over
// the image's honeyfs so `cat /etc/passwd`, `/etc/os-release`, `hostname`, the
// login banner, etc. all tell one coherent, deployment-unique story.
//
// Files are returned keyed by their path under honeyfs/ (e.g. "etc/passwd").

// systemPasswd is a realistic base set of Debian/Ubuntu system accounts. Real
// boxes have these; persona users are appended after them.
const systemPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin`

// serviceAccounts are persona usernames that, in a real system, are service
// accounts (nologin, system home) rather than human login users with /home.
var serviceAccounts = map[string]string{ // username -> home dir
	"www-data": "/var/www", "postgres": "/var/lib/postgresql", "mysql": "/var/lib/mysql",
	"oracle": "/opt/oracle", "dovecot": "/usr/lib/dovecot", "apache": "/var/www",
	"nagios": "/var/lib/nagios", "jenkins": "/var/lib/jenkins", "git": "/var/lib/git",
	"cpanel": "/usr/local/cpanel", "ftpuser": "/srv/ftp", "ubnt": "/home/ubnt",
}

// presentInBase reports whether a username already exists in the system base.
func presentInBase(u string) bool {
	return strings.Contains(systemPasswd, "\n"+u+":") || strings.HasPrefix(systemPasswd, u+":")
}

// generateHoneyfs returns the per-instance honeyfs files for Cowrie, consistent
// with the given persona, distro profile, and hostname.
func generateHoneyfs(t credentialTemplate, p distroProfile, hostname string) map[string]string {
	hostname = sanitizeConfigValue(hostname)
	files := map[string]string{
		"etc/passwd":     etcPasswd(t),
		"etc/group":      etcGroup(t),
		"etc/hostname":   hostname + "\n",
		"etc/os-release": osRelease(p, hostname),
		"etc/issue":      issue(p),
		"etc/motd":       motd(p),
	}
	return files
}

// debianMOTD is the stock /etc/motd shipped on a Debian system.
const debianMOTD = `
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
`

// motd returns the static /etc/motd appropriate for the profile's distro.
// Cowrie's default honeyfs ships the Debian boilerplate on EVERY honeypot, which
// is both a globally-identical fingerprint and a tell on a non-Debian box (the
// os-release says Ubuntu/CentOS but `cat /etc/motd` shows "Debian GNU/Linux").
// Real Ubuntu and CentOS systems have an empty static /etc/motd (their login
// banner is generated dynamically), so only Debian gets the boilerplate.
func motd(p distroProfile) string {
	if strings.Contains(strings.ToLower(p.OSPretty), "debian") {
		return debianMOTD
	}
	return ""
}

// etcPasswd builds /etc/passwd = system base + the persona's accounts, so every
// username the userdb accepts actually exists on the box.
func etcPasswd(t credentialTemplate) string {
	var b strings.Builder
	b.WriteString(systemPasswd)
	b.WriteString("\n")
	uid := 1000
	seen := map[string]bool{}
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || seen[name] || presentInBase(name) {
			continue
		}
		seen[name] = true
		if home, ok := serviceAccounts[name]; ok {
			// Service account: nologin, lower system-ish uid range.
			fmt.Fprintf(&b, "%s:x:%d:%d:%s:%s:/usr/sbin/nologin\n", name, uid, uid, name, home)
		} else {
			fmt.Fprintf(&b, "%s:x:%d:%d:%s,,,:/home/%s:/bin/bash\n", name, uid, uid, name, name)
		}
		uid++
	}
	return b.String()
}

// etcGroup builds a matching /etc/group with a primary group per persona user.
func etcGroup(t credentialTemplate) string {
	var b strings.Builder
	b.WriteString("root:x:0:\nsudo:x:27:\nwww-data:x:33:\nstaff:x:50:\nusers:x:100:\n")
	gid := 1000
	seen := map[string]bool{}
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || seen[name] || presentInBase(name) {
			continue
		}
		seen[name] = true
		fmt.Fprintf(&b, "%s:x:%d:\n", name, gid)
		gid++
	}
	return b.String()
}

// osRelease builds a plausible /etc/os-release consistent with the distro
// profile (so `cat /etc/os-release` agrees with the SSH banner's distro). Stock
// Cowrie ships no os-release at all, which is itself a tell on a modern box.
func osRelease(p distroProfile, hostname string) string {
	pretty := p.OSPretty
	id, name, versionID := "linux", "Linux", ""
	low := strings.ToLower(pretty)
	switch {
	case strings.Contains(low, "ubuntu"):
		id, name = "ubuntu", "Ubuntu"
		versionID = extractVersion(pretty)
	case strings.Contains(low, "debian"):
		id, name = "debian", "Debian GNU/Linux"
		versionID = extractVersion(pretty)
	case strings.Contains(low, "centos"):
		id, name = "centos", "CentOS Linux"
		versionID = extractVersion(pretty)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PRETTY_NAME=\"%s\"\n", pretty)
	fmt.Fprintf(&b, "NAME=\"%s\"\n", name)
	if versionID != "" {
		fmt.Fprintf(&b, "VERSION_ID=\"%s\"\n", versionID)
		fmt.Fprintf(&b, "VERSION=\"%s\"\n", strings.TrimPrefix(pretty, name+" "))
	}
	// VERSION_CODENAME / UBUNTU_CODENAME: real os-release files carry the release
	// codename, and Ubuntu repeats it in UBUNTU_CODENAME. A missing codename on a
	// modern Debian/Ubuntu box is itself a tell.
	if p.Codename != "" {
		fmt.Fprintf(&b, "VERSION_CODENAME=%s\n", p.Codename)
	}
	fmt.Fprintf(&b, "ID=%s\n", id)
	// ID_LIKE places the distro in its family (Ubuntu -> debian, CentOS -> rhel
	// fedora); Debian itself has none.
	if p.IDLike != "" {
		fmt.Fprintf(&b, "ID_LIKE=%s\n", p.IDLike)
	}
	// HOME_URL / SUPPORT_URL / BUG_REPORT_URL round out the file the way a real
	// install has them, with the correct per-distro URLs (Ubuntu uses .com).
	switch id {
	case "ubuntu":
		b.WriteString("HOME_URL=\"https://www.ubuntu.com/\"\n")
		b.WriteString("SUPPORT_URL=\"https://help.ubuntu.com/\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n")
		if p.Codename != "" {
			fmt.Fprintf(&b, "UBUNTU_CODENAME=%s\n", p.Codename)
		}
	case "debian":
		b.WriteString("HOME_URL=\"https://www.debian.org/\"\n")
		b.WriteString("SUPPORT_URL=\"https://www.debian.org/support\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.debian.org/\"\n")
	case "centos":
		b.WriteString("HOME_URL=\"https://www.centos.org/\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.centos.org/\"\n")
	default:
		b.WriteString("HOME_URL=\"https://www." + id + ".org/\"\n")
	}
	return b.String()
}

// issue builds /etc/issue referencing the distro (login banner realism).
func issue(p distroProfile) string {
	return p.OSPretty + " \\n \\l\n\n"
}

// extractVersion pulls the first dotted/numeric version token out of an OS
// pretty name (e.g. "Ubuntu 22.04.3 LTS" -> "22.04").
func extractVersion(pretty string) string {
	for _, tok := range strings.Fields(pretty) {
		if len(tok) > 0 && tok[0] >= '0' && tok[0] <= '9' {
			parts := strings.Split(tok, ".")
			if len(parts) >= 2 {
				return parts[0] + "." + parts[1]
			}
			return parts[0]
		}
	}
	return ""
}
