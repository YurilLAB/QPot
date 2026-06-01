package instance

import "strings"

// credentials.go provides realistic, per-instance login credential sets
// ("personas") for honeypots that authenticate users (Cowrie).
//
// Research basis (SANS ISC "Common usernames"/"origin of passwords"; F5 Labs
// "Top Attacked Usernames and Passwords"; cryptax "Customizing Cowrie"): the
// credentials a honeypot accepts must look like a real system's accounts, not
// authored bait. Each persona pairs a small set of role-appropriate accounts
// (people-name + service accounts, or vendor-default device logins) with
// weak-but-believable passwords drawn from real-world attacker/breach corpora
// (vendor defaults, Season/Company+Year!, sequential digits). Pitfalls avoided:
// no Cowrie phil/richard/pi:raspberry defaults, no obvious bait
// (hacker/test123), no "every password works", no persona/host mismatch, and a
// realistic count (~4-6 accounts) per box.
//
// Cowrie reads these from etc/userdb.txt ("username:x:password"); listing exact
// passwords (no '*' wildcard) means only those credentials succeed — so a human
// who tries the "right" password and then garbage sees consistent behavior.

// credUser is one account and the exact passwords it accepts.
type credUser struct {
	Username  string
	Passwords []string
}

// credentialTemplate is a believable system persona.
type credentialTemplate struct {
	Name        string // stable id operators can pin via stealth.credential_template
	Description string
	Users       []credUser
}

// credentialTemplates are 10 internally-consistent system personas. Sourced
// from real attacker credential studies (see file header). Each is a plausible
// internet-exposed box with a handful of working accounts.
var credentialTemplates = []credentialTemplate{
	{
		Name: "corp-ubuntu", Description: "Corporate Ubuntu application server",
		Users: []credUser{
			{"jmartin", []string{"Summer2023!", "Welcome1"}},
			{"swilson", []string{"Acme2024!"}},
			{"deploy", []string{"d3pl0y2023", "deploy"}},
			{"ubuntu", []string{"ubuntu"}},
			{"backup", []string{"Backup#2023"}},
		},
	},
	{
		Name: "edge-router", Description: "Edge router / firewall (Ubiquiti-style)",
		Users: []credUser{
			{"ubnt", []string{"ubnt"}},
			{"admin", []string{"admin", "password"}},
			{"root", []string{"password", "12345"}},
			{"support", []string{"support"}},
		},
	},
	{
		Name: "web-hosting", Description: "Web hosting box (cPanel/WHM)",
		Users: []credUser{
			{"cpanel", []string{"cpanel"}},
			{"admin", []string{"Welcome1", "changeme"}},
			{"www-data", []string{"webadmin2023"}},
			{"user1", []string{"changeme"}},
			{"ftpuser", []string{"ftpuser", "ftp123"}},
		},
	},
	{
		Name: "db-server", Description: "Database server (Oracle/Postgres/MySQL)",
		Users: []credUser{
			{"oracle", []string{"oracle"}},
			{"postgres", []string{"postgres"}},
			{"mysql", []string{"mysql"}},
			{"dbadmin", []string{"DBadmin2023!"}},
			{"root", []string{"Passw0rd"}},
		},
	},
	{
		Name: "dev-ci", Description: "Dev / CI box (cloud image)",
		Users: []credUser{
			{"ec2-user", []string{"ec2-user"}},
			{"ubuntu", []string{"ubuntu"}},
			{"vagrant", []string{"vagrant"}},
			{"jenkins", []string{"jenkins123"}},
			{"git", []string{"git"}},
			{"devops", []string{"DevOps2024!"}},
		},
	},
	{
		Name: "nas-storage", Description: "NAS / storage appliance (Synology/QNAP-style)",
		Users: []credUser{
			{"admin", []string{"admin"}},
			{"nasadmin", []string{"Synology123"}},
			{"guest", []string{"guest"}},
			{"media", []string{"media2023"}},
		},
	},
	{
		Name: "iot-camera", Description: "IoT camera / DVR",
		Users: []credUser{
			{"admin", []string{"7ujMko0admin", "admin12345"}}, // Dahua/Hikvision default
			{"root", []string{"12345"}},
			{"user", []string{"user"}},
			{"support", []string{"support"}},
		},
	},
	{
		Name: "mail-server", Description: "Mail server (Postfix/Dovecot)",
		Users: []credUser{
			{"postmaster", []string{"Postmaster1"}},
			{"admin", []string{"MailAdmin2023!"}},
			{"dovecot", []string{"dovecot"}},
			{"mailuser", []string{"Welcome123"}},
			{"root", []string{"Mail#2024"}},
		},
	},
	{
		Name: "k8s-node", Description: "Kubernetes worker node",
		Users: []credUser{
			{"core", []string{"core"}},
			{"ubuntu", []string{"kubeadmin2023"}},
			{"kube", []string{"Kube#2024"}},
			{"deploy", []string{"deploy123"}},
			{"root", []string{"K8sadmin!"}},
		},
	},
	{
		Name: "legacy-centos", Description: "Legacy CentOS server",
		Users: []credUser{
			{"root", []string{"redhat"}},
			{"centos", []string{"centos"}},
			{"oracle", []string{"oracle123"}},
			{"nagios", []string{"nagios"}},
			{"apache", []string{"Apache2019!"}},
			{"svc_backup", []string{"Backup2019"}},
		},
	},
	{
		Name: "soho-router", Description: "Home/SOHO router with shell (OpenWrt/Mikrotik)",
		Users: []credUser{
			{"root", []string{"admin", "root"}},
			{"admin", []string{"admin", "1234"}},
			{"user", []string{"user"}},
		},
	},
	{
		Name: "voip-pbx", Description: "VoIP / PBX appliance (Asterisk/FreePBX)",
		Users: []credUser{
			{"asterisk", []string{"asterisk"}},
			{"asteriskftp", []string{"asteriskftp"}}, // appears in real F5 attack data
			{"freepbx", []string{"freepbx"}},
			{"sip", []string{"sip123"}},
			{"root", []string{"Voip2023!"}},
		},
	},
	{
		Name: "cctv-nvr", Description: "CCTV NVR / DVR (Hikvision/Dahua firmware)",
		Users: []credUser{
			{"admin", []string{"12345", "admin12345"}}, // Hikvision default
			{"root", []string{"7ujMko0admin", "vizxv"}}, // Dahua defaults
			{"888888", []string{"888888"}},               // Dahua default account
			{"default", []string{"default"}},
		},
	},
	{
		Name: "cloud-default", Description: "Cloud image, default accounts only",
		Users: []credUser{
			{"ubuntu", []string{"ubuntu"}},
			{"ec2-user", []string{"ec2-user"}},
			{"admin", []string{"admin"}},
		},
	},
	{
		Name: "abandoned-vps", Description: "Bare / abandoned VPS (few weak accounts)",
		Users: []credUser{
			{"root", []string{"123456", "toor"}},
			{"user", []string{"password"}},
		},
	},
	{
		Name: "game-server", Description: "Game/voice server (TeamSpeak/Steam/Minecraft)",
		Users: []credUser{
			{"ts3", []string{"ts3"}}, // appears in real F5 attack data
			{"steam", []string{"steam"}},
			{"minecraft", []string{"minecraft123"}},
			{"server", []string{"server2023"}},
		},
	},
}

// credentialTemplateByName returns the template with the given name, or false.
func credentialTemplateByName(name string) (credentialTemplate, bool) {
	for _, t := range credentialTemplates {
		if t.Name == name {
			return t, true
		}
	}
	return credentialTemplate{}, false
}

// selectCredentialTemplate picks the persona for an instance. An explicit,
// known name (from stealth.credential_template) wins; otherwise QPot
// deterministically auto-selects one per instance from the seed, so each
// deployment looks like a distinct real system instead of a shared signature.
func selectCredentialTemplate(explicit, seed string) credentialTemplate {
	if explicit != "" {
		if t, ok := credentialTemplateByName(explicit); ok {
			return t
		}
	}
	return credentialTemplates[seededIndex("cred:"+seed, len(credentialTemplates))]
}

// renderCowrieUserDB renders a credential template into Cowrie userdb.txt
// format. Only the listed passwords are accepted for each account.
func renderCowrieUserDB(t credentialTemplate) string {
	var b strings.Builder
	// ASCII only: cowrie reads userdb.txt as ASCII and a non-ASCII byte aborts
	// parsing (the whole userdb is then ignored), so never use em-dashes etc.
	b.WriteString("# QPot-generated Cowrie userdb - persona: " + t.Name + "\n")
	b.WriteString("# " + t.Description + "\n")
	b.WriteString("# format: username:x:password   ('*' = any, '!x' = deny x)\n")
	for _, u := range t.Users {
		user := sanitizeConfigValue(u.Username)
		if user == "" {
			continue
		}
		for _, p := range u.Passwords {
			b.WriteString(user + ":x:" + sanitizeConfigValue(p) + "\n")
		}
	}
	return b.String()
}

// sanitizeConfigValue strips control characters/newlines and caps length on a
// value that will be interpolated into a single line of a generated config
// (cowrie.cfg, userdb.txt). This prevents a stray newline in operator-supplied
// stealth/credential strings from injecting extra config directives.
func sanitizeConfigValue(s string) string {
	// Keep only printable ASCII. Control chars/newlines could inject config
	// directives, and non-ASCII bytes abort cowrie's ASCII parse of
	// cowrie.cfg/userdb.txt (silently disabling the whole file).
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
