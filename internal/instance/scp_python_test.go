package instance

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/canary"
)

// The OpenSSH output these tests compare with was recorded from OpenSSH
// 10.0p2 (Debian 13), in the network namespace of the curl tests (10.66.0.5
// drops every packet, 127.0.0.1:1 refuses); the usage texts and messages of
// the older releases are those of their sources (scp.c, sftp.c,
// sftp-client.c at V_7_4_P1, V_8_7_P1, V_8_9_P1, V_9_2_P1, V_9_6_P1).

const (
	scpUsage10 = "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n" +
		"           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n" +
		"           [-P port] [-S program] [-X sftp_option] source ... target\n"
	sftpUsage10 = "usage: sftp [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n" +
		"          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n" +
		"          [-J destination] [-l limit] [-o ssh_option] [-P port]\n" +
		"          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n" +
		"          [-X sftp_option] destination\n"
	scpTimedOut  = "ssh: connect to host 10.66.0.5 port 22: Connection timed out\r\n"
	scpRefused   = "ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n"
	sftpClosed   = "\rConnection closed.  \nConnection closed\r\n"
	scpConfigDB1 = "Host db01\n  HostName 10.66.0.7\n  User backup\n  IdentityFile /root/.ssh/k\n  ConnectTimeout 2\n"
)

// sshVersions are the [shell] ssh_version lines of the personas.
var sshVersions = map[string]string{
	"debian-13":    "OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026",
	"debian-12":    "OpenSSH_9.2p1 Debian-2+deb12u7, OpenSSL 3.0.17 1 Jul 2025",
	"ubuntu-24.04": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.14, OpenSSL 3.0.13 30 Jan 2024",
	"ubuntu-22.04": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.13, OpenSSL 3.0.2 15 Mar 2022",
	"rhel-9":       "OpenSSH_8.7p1, OpenSSL 3.2.2 4 Jun 2024",
	"centos-7":     "OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017",
}

// scpCase is an scp or sftp command line on a persona, with a file to send
// and an ssh config naming db01.
func scpCase(persona string, argv ...string) stubCase {
	return stubCase{"argv": argv, "persona": persona, "terminal": true,
		"config": map[string]any{"shell.ssh_version": sshVersions[persona]},
		"files": map[string]any{"/root/f": "hi\n", "/root/cfg": scpConfigDB1, "/dev": map[string]any{"dir": true},
			"/dev/null": ""}}
}

// TestScpSftpLikeOpenSSH: scp's and sftp's usage, option errors, waits and
// failures at an address that never answers or refuses, as OpenSSH 10.0p2
// gave them, and those of the older releases' sources.
func TestScpSftpLikeOpenSSH(t *testing.T) {
	d13 := func(argv ...string) stubCase { return scpCase("debian-13", argv...) }
	cases := []struct {
		c    stubCase
		want stubWant
	}{
		{d13("scp"), stubWant{"", scpUsage10, 1, 0}},
		{d13("sftp"), stubWant{"", sftpUsage10, 1, 0}},
		{d13("scp", "/root/f"), stubWant{"", scpUsage10, 1, 0}},
		{d13("scp", "-i"), stubWant{"", "scp: option requires an argument -- i\r\n" + scpUsage10, 1, 0}},
		{d13("scp", "-Z", "f", "x:"), stubWant{"", "scp: unknown option -- Z\r\n" + scpUsage10, 1, 0}},
		{d13("sftp", "-Z"), stubWant{"", "unknown option -- Z\r\n" + sftpUsage10, 1, 0}},
		{d13("scp", "-o", "ConnectTimeout=2", "-i", "/root/.ssh/k", "/root/f", "root@10.66.0.5:/tmp/"),
			stubWant{"", scpTimedOut + "scp: Connection closed\r\n", 255, 2}},
		{d13("scp", "-O", "-o", "ConnectTimeout=2", "-i", "/root/.ssh/k", "/root/f", "root@10.66.0.5:/tmp/"),
			stubWant{"", scpTimedOut + "lost connection\n", 1, 2}},
		{d13("scp", "-q", "-o", "ConnectTimeout=2", "/root/f", "root@10.66.0.5:"),
			stubWant{"", "scp: Connection closed\r\n", 255, 2}},
		{d13("scp", "-O", "-q", "-o", "ConnectTimeout=2", "/root/f", "root@10.66.0.5:"), stubWant{"", "lost connection\n", 1, 2}},
		{d13("scp", "-o", "ConnectTimeout=2", "root@10.66.0.5:/etc/passwd", "/tmp/"),
			stubWant{"", scpTimedOut + "scp: Connection closed\r\n", 255, 2}},
		{d13("scp", "-P", "1", "/root/f", "root@127.0.0.1:/tmp/"), stubWant{"", scpRefused + "scp: Connection closed\r\n", 255, 0}},
		{d13("scp", "-O", "-P", "1", "/root/f", "root@127.0.0.1:/tmp/"), stubWant{"", scpRefused + "lost connection\n", 1, 0}},
		{d13("scp", "-F", "/root/cfg", "/root/f", "db01:/tmp/"),
			stubWant{"", "ssh: connect to host 10.66.0.7 port 22: Connection timed out\r\nscp: Connection closed\r\n", 255, 2}},
		{d13("scp", "-r", "-o", "ConnectTimeout=2", "/root", "10.66.0.5:/tmp/"),
			stubWant{"", scpTimedOut + "scp: Connection closed\r\n", 255, 2}},
		{d13("scp", "/root/nope", "x@10.66.0.5:"),
			stubWant{"", "scp: stat local \"/root/nope\": No such file or directory\r\n", 255, 0}},
		// no ConnectTimeout: the kernel's SYN retries
		{d13("scp", "/root/f", "10.66.0.5:"), stubWant{"", scpTimedOut + "scp: Connection closed\r\n", 255, 127}},
		{d13("sftp", "-o", "ConnectTimeout=2", "-i", "/root/.ssh/k", "root@10.66.0.5"),
			stubWant{"", scpTimedOut + sftpClosed, 255, 2}},
		{d13("sftp", "-o", "ConnectTimeout=2", "root@10.66.0.5:/etc/passwd"), stubWant{"", scpTimedOut + sftpClosed, 255, 2}},
		{d13("sftp", "-P", "1", "root@127.0.0.1"), stubWant{"", scpRefused + sftpClosed, 255, 0}},
		{d13("sftp", "-F", "/root/cfg", "db01"),
			stubWant{"", "ssh: connect to host 10.66.0.7 port 22: Connection timed out\r\n" + sftpClosed, 255, 2}},
		{d13("sftp", "-b", "/dev/null", "-o", "ConnectTimeout=2", "10.66.0.5"),
			stubWant{"", scpTimedOut + "Connection closed\r\n", 255, 2}},
		// -X (9.2 and later): fatal for a value it does not take (recorded from 10.0p2; 9.2's and 9.6's
		// scp.c and sftp.c have the same code)
		{d13("scp", "-X", "x", "/root/f", "10.66.0.5:"), stubWant{"", "scp: Invalid -X option\r\n", 255, 0}},
		{d13("scp", "-X", "buffer=0", "/root/f", "10.66.0.5:"),
			stubWant{"", "scp: Invalid buffer size \"0\": Invalid argument\r\n", 255, 0}},
		{d13("scp", "-X", "buffer=x", "/root/f", "10.66.0.5:"),
			stubWant{"", "scp: Invalid buffer size \"x\": Invalid argument\r\n", 255, 0}},
		{d13("scp", "-X", "nrequests=0", "/root/f", "10.66.0.5:"),
			stubWant{"", "scp: Invalid number of requests \"0\": too small\r\n", 255, 0}},
		{d13("scp", "-X", "nrequests=5", "-o", "ConnectTimeout=2", "/root/f", "10.66.0.5:"),
			stubWant{"", scpTimedOut + "scp: Connection closed\r\n", 255, 2}},
		{d13("sftp", "-X", "x", "10.66.0.5"), stubWant{"", "Invalid -X option\r\n", 255, 0}},
		{d13("sftp", "-X", "buffer=999999999", "10.66.0.5"),
			stubWant{"", "Invalid buffer size \"999999999\": Invalid argument\r\n", 255, 0}},
		// the older releases (from their sources)
		{scpCase("centos-7", "scp"), stubWant{"", "usage: scp [-12346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]\n" +
			"           [-l limit] [-o ssh_option] [-P port] [-S program]\n" +
			"           [[user@]host1:]file1 ... [[user@]host2:]file2\n", 1, 0}},
		{scpCase("centos-7", "scp", "-J", "x", "/root/f", "x:"), stubWant{"", "scp: unknown option -- J\r\n" +
			"usage: scp [-12346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]\n" +
			"           [-l limit] [-o ssh_option] [-P port] [-S program]\n" +
			"           [[user@]host1:]file1 ... [[user@]host2:]file2\n", 1, 0}},
		{scpCase("centos-7", "scp", "-o", "ConnectTimeout=2", "/root/f", "10.66.0.5:"),
			stubWant{"", scpTimedOut + "lost connection\n", 1, 2}},
		{scpCase("centos-7", "sftp", "-o", "ConnectTimeout=2", "10.66.0.5"),
			stubWant{"", scpTimedOut + "Connection closed\r\n", 255, 2}},
		{scpCase("centos-7", "sftp"), stubWant{"", "usage: sftp [-1246aCfpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n" +
			"          [-D sftp_server_path] [-F ssh_config] [-i identity_file] [-l limit]\n" +
			"          [-o ssh_option] [-P port] [-R num_requests] [-S program]\n" +
			"          [-s subsystem | sftp_server] host\n" +
			"       sftp [user@]host[:file ...]\n" +
			"       sftp [user@]host[:dir[/]]\n" +
			"       sftp -b batchfile [user@]host\n", 1, 0}},
		// -M is 8.7's (legacy mode: the local file is looked at only once connected)
		{scpCase("rhel-9", "scp", "-M", "x", "/root/nope", "10.66.0.5:"), stubWant{"", scpTimedOut + "lost connection\n", 1, 127}},
		{scpCase("rhel-9", "scp", "-X", "x", "/root/f", "10.66.0.5:"), stubWant{"", "scp: unknown option -- X\r\n" + scpUsage87, 1, 0}},
		{scpCase("rhel-9", "scp", "-o", "ConnectTimeout=2", "/root/f", "10.66.0.5:"),
			stubWant{"", scpTimedOut + "lost connection\n", 1, 2}},
		{scpCase("rhel-9", "sftp", "-q", "-b", "/dev/null", "-o", "ConnectTimeout=2", "10.66.0.5"),
			stubWant{"", sftpClosed, 255, 2}},
		{scpCase("ubuntu-22.04", "sftp", "-o", "ConnectTimeout=2", "10.66.0.5"), stubWant{"", scpTimedOut + sftpClosed, 255, 2}},
		{scpCase("debian-12", "sftp", "-q", "-o", "ConnectTimeout=2", "10.66.0.5"), stubWant{"", "Connection closed\r\n", 255, 2}},
		{scpCase("ubuntu-24.04", "scp", "-o", "ConnectTimeout=2", "/root/f", "10.66.0.5:"),
			stubWant{"", scpTimedOut + "scp: Connection closed\r\n", 255, 2}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		checkStub(t, c.c["persona"].(string)+": "+argvLabel(c.c), got[i], c.want)
	}
	// scp between two local paths is cp
	local := runCowrieStub(t, []stubCase{scpCase("debian-13", "scp", "-p", "/root/f", "/root/g")})[0]
	if len(local.Exec) != 1 || strings.Join(local.Exec[0], " ") != "Command_cp -p -- /root/f /root/g" {
		t.Errorf("local scp: %v", local.Exec)
	}
}

// scpUsage87 is scp's usage of OpenSSH 8.7 and 8.9 (scp.c).
const scpUsage87 = "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n" +
	"           [-i identity_file] [-J destination] [-l limit]\n" +
	"           [-o ssh_option] [-P port] [-S program] source ... target\n"

// TestScpSftpLogTheKeysTheyWouldOffer: scp and sftp log the identity files
// they would offer as ssh does (-i, -o IdentityFile, the matching Host of
// the config or -F, else the default files), so a planted key used with
// them (scp -i ~/.ssh/id_ed25519 dump.sql backup@db01:) trips its canary.
func TestScpSftpLogTheKeysTheyWouldOffer(t *testing.T) {
	key := canary.NewDeriver("scp-harness").Ed25519Key("root-key")
	blob := canary.Ed25519PublicBlob(key.Public().(ed25519.PublicKey))
	priv := canary.MarshalEd25519PrivateKey(key, "backup@corp", 7)
	fp := canary.MD5Fingerprint(blob)
	b64 := func(s string) map[string]any {
		return map[string]any{"b64": base64.StdEncoding.EncodeToString([]byte(s)), "mode": 0o600}
	}
	plan := map[string]any{"hosts": []map[string]any{{"ip": "10.158.124.18", "names": []string{"db01", "db01.corp.internal"}}}}
	mk := func(argv ...string) stubCase {
		c := scpCase("debian-13", argv...)
		files := c["files"].(map[string]any)
		files["/root/.ssh/id_ed25519"] = b64(string(priv))
		files["/root/.ssh/config"] = b64("Host db01\n    User backup\n    IdentityFile ~/.ssh/id_ed25519\n")
		files["/srv/k"] = b64(string(priv))
		c["plan"] = plan
		return c
	}
	cases := []struct {
		c        stubCase
		user     string
		identity string
		seconds  float64
	}{
		{mk("scp", "-i", "/root/.ssh/id_ed25519", "/root/f", "backup@db01:/tmp/"), "backup", "/root/.ssh/id_ed25519", 127},
		{mk("scp", "-o", "ConnectTimeout=5", "/root/f", "db01:"), "backup", "/root/.ssh/id_ed25519", 5},
		{mk("scp", "-o", "IdentityFile=/srv/k", "-o", "ConnectTimeout=3", "root@db01.corp.internal:/etc/passwd", "/tmp/"),
			"root", "/srv/k", 3},
		{mk("sftp", "-i", "/srv/k", "-o", "ConnectTimeout=4", "u@10.158.124.18"), "u", "/srv/k", 4},
		{mk("sftp", "-oIdentityFile /srv/k", "-oConnectTimeout=4", "db01"), "backup", "/srv/k", 4},
		{mk("scp", "-3", "-r", "-l", "100", "-P", "2222", "-c", "aes128-ctr", "-o", "ConnectTimeout 2", "/root/f", "db01:"),
			"backup", "/root/.ssh/id_ed25519", 2},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		label := argvLabel(c.c)
		var used []map[string]any
		for _, e := range got[i].Events {
			if e["eventid"] == "cowrie.credentials.use" {
				used = append(used, e)
			}
		}
		if len(used) != 1 {
			t.Errorf("%s: %d key events: %v", label, len(used), got[i].Events)
			continue
		}
		e := used[0]
		prog := c.c["argv"].([]string)[0]
		if e["fingerprint"] != fp || e["key"] != "ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob) || e["realm"] != "ssh" ||
			e["username"] != c.user || e["identity"] != c.identity || !strings.HasPrefix(e["input"].(string), prog+" ") {
			t.Errorf("%s: event %v", label, e)
		}
		if got[i].Seconds != c.seconds || got[i].code() != 255 && got[i].code() != 1 {
			t.Errorf("%s: %d after %.1f s, want %.0f s", label, got[i].code(), got[i].Seconds, c.seconds)
		}
		if len(got[i].Lookups) != 0 || len(got[i].Fetches) != 0 {
			t.Errorf("%s: reached the network: %v %v", label, got[i].Lookups, got[i].Fetches)
		}
	}
}

// TestScpPromptsAndPasswords: a host that answers asks about its key, takes
// the passwords (each logged as typed) and refuses them; ^C stops a wait.
func TestScpPromptsAndPasswords(t *testing.T) {
	c := scpCase("debian-13", "scp", "/root/f", "admin@93.184.215.14:/tmp/")
	c["lines"] = []string{"yes", "@0.1", "hunter2", "@3", "letmein", "@3", "x", "@3"}
	strict := scpCase("debian-13", "scp", "-o", "StrictHostKeyChecking=no", "-o", "NumberOfPasswordPrompts=1", "/root/f",
		"93.184.215.14:")
	strict["lines"] = []string{"pw", "@3"}
	batch := scpCase("ubuntu-22.04", "sftp", "-o", "BatchMode=yes", "93.184.215.14")
	stop := scpCase("debian-13", "scp", "/root/f", "10.66.0.5:")
	stop["lines"] = []string{"@5", "^C"}
	got := runCowrieStub(t, []stubCase{c, strict, batch, stop})
	e := got[0].Stderr
	for _, want := range []string{
		"The authenticity of host '93.184.215.14 (93.184.215.14)' can't be established.\r\nED25519 key fingerprint is SHA256:",
		"This key is not known by any other names.\r\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ",
		"Warning: Permanently added '93.184.215.14' (ED25519) to the list of known hosts.\r\nadmin@93.184.215.14's password: ",
		"Permission denied, please try again.\r\nadmin@93.184.215.14's password: ",
		"admin@93.184.215.14: Permission denied (publickey,password).\r\nscp: Connection closed\r\n",
	} {
		if !strings.Contains(e, want) {
			t.Errorf("scp to a host that answers lacks %q:\n%q", want, e)
		}
	}
	var typed []string
	for _, ev := range got[0].Events {
		if ev["eventid"] == "cowrie.command.input" && ev["realm"] == "scp" {
			typed = append(typed, ev["input"].(string))
		}
	}
	// nothing of scp's own on stdout: the new line after a password is the terminal's Enter (a newline
	// of scp's own made two, live)
	if got[0].Stdout != "" || got[1].Stdout != "" {
		t.Errorf("scp wrote %q and %q to stdout", got[0].Stdout, got[1].Stdout)
	}
	if strings.Join(typed, ",") != "yes,hunter2,letmein,x" || got[0].code() != 255 || got[0].PasswordInput {
		t.Errorf("typed %v, code %d, password input left %v", typed, got[0].code(), got[0].PasswordInput)
	}
	if e := got[1].Stderr; !strings.HasPrefix(e, "Warning: Permanently added '93.184.215.14' (ED25519) to the list of known hosts.\r\n") ||
		!strings.HasSuffix(e, "root@93.184.215.14: Permission denied (publickey,password).\r\nscp: Connection closed\r\n") ||
		strings.Count(e, "password: ") != 1 {
		t.Errorf("StrictHostKeyChecking=no, one prompt: %q", e)
	}
	if got[2].Stderr != "Host key verification failed.\r\n"+sftpClosed || got[2].code() != 255 {
		t.Errorf("sftp in batch mode: %d %q", got[2].code(), got[2].Stderr)
	}
	if got[3].Seconds != 5 || !got[3].Exited || len(got[3].Events) > 1 {
		t.Errorf("^C during the wait: exited %v after %.1f s", got[3].Exited, got[3].Seconds)
	}
}

// TestScpParsesInLinearTime: options and config lines of the attacker's
// own making (a long run of blanks in a keyword's separator, thousands of
// -o, a huge Host line) are read in linear time, as ssh's are since the
// fix of its quadratic separator.
func TestScpParsesInLinearTime(t *testing.T) {
	blanks := strings.Repeat(" ", 64000)
	many := []string{"scp"}
	for i := 0; i < 2000; i++ {
		many = append(many, "-o", "ConnectTimeout"+strings.Repeat(" ", 30)+"=x")
	}
	many = append(many, "/root/f", "10.66.0.5:")
	hostLine := "Host" + blanks + strings.Repeat("*a", 2000) + "\n  IdentityFile /srv/k\n" +
		"ConnectTimeout" + blanks + "=" + blanks + "x\n"
	cfg := scpCase("debian-13", "scp", "-F", "/root/huge", "/root/f", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab:")
	cfg["files"].(map[string]any)["/root/huge"] = hostLine
	cases := []stubCase{
		scpCase("debian-13", "scp", "-o", "IdentityFile"+blanks+"/tmp/"+strings.Repeat("x", 2000), "/root/f", "10.66.0.5:"),
		scpCase("debian-13", "sftp", "-o", "ConnectTimeout"+blanks+"="+blanks+"x", "10.66.0.5"),
		scpCase("debian-13", many...),
		cfg,
		// HostName's %h is the host as typed: 2000 of them and a host of 200 KB are no 400 MB name
		scpCase("debian-13", "scp", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o",
			"HostName="+strings.Repeat("%h", 2000), "/root/f", strings.Repeat("h", 200000)+":"),
	}
	for _, c := range cases {
		c["memory"] = true
	}
	got := runCowrieStub(t, cases)
	for i, r := range got {
		// the inputs are at most a few hundred KB: no command line makes much more than that
		if r.CPU > 0.5 || r.Peak > 16<<20 {
			t.Errorf("case %d took %.3f s of CPU, %d bytes at its peak", i, r.CPU, r.Peak)
		}
		t.Logf("case %d: %.4f s CPU, %d KiB at the peak", i, r.CPU, r.Peak>>10)
	}
}
