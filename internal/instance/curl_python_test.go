package instance

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The real tools' output these tests compare with was recorded from curl
// 8.14.1 and GNU wget 1.25.0 (Debian 13) in a network namespace where
// 127.0.0.1:1 refuses, 10.66.0.5 drops every packet and a local server
// answers on 127.0.0.1:8080 (here a public address, as Cowrie fetches only
// those); the older releases' texts are those of their own sources.

const (
	curlTry  = "curl: try 'curl --help' or 'curl --manual' for more information\n"
	curlHTTP = "93.184.215.14:8080"
	// the meter curl draws when its output is no terminal and nothing arrives
	curlMeterHead = "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n" +
		"                                 Dload  Upload   Total   Spent    Left  Speed\n"
	curlMeterZero = "\r  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0"
)

// curlServer is what the recorded server answered.
func curlServer() map[string]any {
	page := func(code int, phrase, body string) map[string]any {
		return map[string]any{"code": code, "phrase": phrase, "body": body}
	}
	return map[string]any{
		"http://" + curlHTTP + "/ok":      page(200, "OK", "hello\n"),
		"http://" + curlHTTP + "/missing": page(404, "Not Found", "<html>error</html>\n"),
		"http://" + curlHTTP + "/err":     page(500, "Internal Server Error", "<html>error</html>\n"),
		"http://" + curlHTTP + "/unavail": page(503, "Service Unavailable", "<html>error</html>\n"),
		"http://" + curlHTTP + "/redir":   page(302, "Found", "<html>error</html>\n"),
	}
}

// curlCase is a curl (or wget) command line on Debian 13 whose output is
// not a terminal (as when it was recorded).
func curlCase(argv ...string) stubCase {
	return stubCase{"argv": argv, "persona": "debian-13", "terminal": false, "http": curlServer(),
		"dns":   map[string]any{"nosuch.invalid": nil},
		"files": map[string]any{"/dev": map[string]any{"dir": true}, "/dev/null": ""}}
}

// TestCurlLikeCurl: curl's options, messages, exit statuses and waits as
// curl 8.14.1 gave them; an address the honeypot does not contact refuses
// (loopback) or times out (a private one) instead of "could not resolve".
func TestCurlLikeCurl(t *testing.T) {
	u := "http://" + curlHTTP
	refused := "curl: (7) Failed to connect to 127.0.0.1 port 1 after 1 ms: Could not connect to server\n"
	timedOut := "curl: (28) Connection timed out after 3002 milliseconds\n"
	kernel := "curl: (28) Failed to connect to 10.66.0.5 port 80 after 127133 ms: Could not connect to server\n"
	type tc struct {
		c    stubCase
		want stubWant
	}
	cases := []tc{
		{curlCase("curl", "-sS", "http://127.0.0.1:1/"), stubWant{"", refused, 7, 0}},
		{curlCase("curl", "http://127.0.0.1:1/"),
			stubWant{"", curlMeterHead + curlMeterZero + curlMeterZero + "\n" + refused, 7, 0}},
		{curlCase("curl", "-s", "http://127.0.0.1:1/"), stubWant{"", "", 7, 0}},
		{curlCase("curl", "-fsS", "-m", "3", "http://10.66.0.5/ping/x"), stubWant{"", timedOut, 28, 3}},
		{curlCase("curl", "-fsS", "-m", "3", "--retry", "2", "http://10.66.0.5/ping/x"),
			stubWant{"", strings.Repeat(timedOut, 3), 28, 12}},
		{curlCase("curl", "-sS", "-m", "3", "--retry", "1", "http://10.66.0.5/ping/x"),
			stubWant{"", strings.Repeat(timedOut, 2), 28, 7}},
		{curlCase("curl", "-fsS", "-m", "3", "--retry", "3", "http://10.66.0.5/ping/y"),
			stubWant{"", strings.Repeat(timedOut, 4), 28, 19}},
		{curlCase("curl", "-sS", "--connect-timeout", "2", "-m", "5", "http://10.66.0.5/"),
			stubWant{"", "curl: (28) Connection timed out after 2002 milliseconds\n", 28, 2}},
		// no limit of curl's own: the kernel's SYN retries (127 s) end the try
		{curlCase("curl", "-sS", "http://10.66.0.5/"), stubWant{"", kernel, 28, 127}},
		{curlCase("curl", "-sS", "--retry", "2", "http://10.66.0.5/"), stubWant{"", strings.Repeat(kernel, 3), 28, 384}},
		// a limit of curl's own longer than the kernel's wait: the kernel gives up first (recorded with
		// tcp_syn_retries 2: -m 20 and --connect-timeout 20 failed after 7138 ms as without them)
		{curlCase("curl", "-sS", "-m", "200", "http://10.66.0.5/"), stubWant{"", kernel, 28, 127}},
		{curlCase("curl", "-sS", "--connect-timeout", "300", "-m", "400", "http://10.66.0.5/"), stubWant{"", kernel, 28, 127}},
		{curlCase("curl", "-sS", "-m", "127", "http://10.66.0.5/"),
			stubWant{"", "curl: (28) Connection timed out after 127001 milliseconds\n", 28, 127}},
		{curlCase("curl", "-s", "-m", "0.5", "http://10.66.0.5/"), stubWant{"", "", 28, 0.5}},
		{curlCase("curl", "-sS", "-m", "1.5", "http://10.66.0.5/"),
			stubWant{"", "curl: (28) Connection timed out after 1502 milliseconds\n", 28, 1.5}},
		{curlCase("curl", "-sf", u+"/missing"), stubWant{"", "", 22, 0}},
		{curlCase("curl", "-sSf", u+"/missing"), stubWant{"", "curl: (22) The requested URL returned error: 404\n", 22, 0}},
		{curlCase("curl", "-sSf", u+"/err"), stubWant{"", "curl: (22) The requested URL returned error: 500\n", 22, 0}},
		{curlCase("curl", "-sSf", "--retry", "1", u+"/unavail"),
			stubWant{"", strings.Repeat("curl: (22) The requested URL returned error: 503\n", 2), 22, 1}},
		{curlCase("curl", "-sf", "--retry", "1", u+"/unavail"), stubWant{"", "", 22, 1}},
		{curlCase("curl", "-s", u+"/missing"), stubWant{"<html>error</html>\n", "", 0, 0}},
		{curlCase("curl", "-s", u+"/redir"), stubWant{"<html>error</html>\n", "", 0, 0}},
		{curlCase("curl", "-s", "-o", "/dev/null", "-w", `%{http_code}\n`, u+"/ok"), stubWant{"200\n", "", 0, 0}},
		{curlCase("curl", "-s", "-o", "/dev/null", "-w", `%{http_code}\n`, "http://127.0.0.1:1/"),
			stubWant{"000\n", "", 7, 0}},
		{curlCase("curl", "-s", "-w", `[%{http_code}|%{response_code}|%{size_download}|%{url_effective}|%{content_type}|`+
			`%{remote_ip}|%{remote_port}|%{exitcode}|%{num_redirects}|%{scheme}|%{redirect_url}|%{errormsg}|%{method}]\n`,
			u+"/ok"),
			stubWant{"hello\n[200|200|6|" + u + "/ok|text/plain|93.184.215.14|8080|0|0|http|||GET]\n", "", 0, 0}},
		{curlCase("curl", "-s", "-w", `[%{http_code}|%{response_code}|%{size_download}|%{url_effective}|%{content_type}|`+
			`%{remote_ip}|%{remote_port}|%{exitcode}|%{num_redirects}|%{scheme}|%{http_version}|%{redirect_url}|%{errormsg}]\n`,
			"http://127.0.0.1:1/"),
			stubWant{"[000|000|0|http://127.0.0.1:1/|||-1|7|0|http|0||Failed to connect to 127.0.0.1 port 1 after 0 ms: " +
				"Could not connect to server]\n", "", 7, 0}},
		{curlCase("curl", "-s", "-w", `%{nosuch}|%{http_code}|%%|\t|%|%{`, "-o", "/dev/null", u+"/ok"),
			stubWant{"|200|%|\t|%|%{", "curl: unknown --write-out variable: 'nosuch'\n", 0, 0}},
		{curlCase("curl", "--nope", u+"/ok"), stubWant{"", "curl: option --nope: is unknown\n" + curlTry, 2, 0}},
		{curlCase("curl", "-m"), stubWant{"", "curl: option -m: requires parameter\n" + curlTry, 2, 0}},
		{curlCase("curl", "-m", "abc", u+"/ok"),
			stubWant{"", "curl: option -m: expected a proper numerical parameter\n" + curlTry, 2, 0}},
		{curlCase("curl", "--retry", "x", u+"/ok"),
			stubWant{"", "curl: option --retry: expected a proper numerical parameter\n" + curlTry, 2, 0}},
		{curlCase("curl", "--max-time=5", u+"/ok"), stubWant{"", "curl: option --max-time=5: is unknown\n" + curlTry, 2, 0}},
		{curlCase("curl"), stubWant{"", curlTry, 2, 0}},
		{curlCase("curl", "-s"), stubWant{"", "curl: (2) no URL specified\n" + curlTry, 2, 0}},
		{curlCase("curl", "-fsSLk", "-H", "X: y", "-d", "a=b", "-X", "POST", "-u", "u:p", "-A", "ua", "--connect-timeout", "2",
			"-o", "/dev/null", u+"/ok"), stubWant{"", "", 0, 0}},
		{curlCase("curl", "-sS", "http://nosuch.invalid/"), stubWant{"", "curl: (6) Could not resolve host: nosuch.invalid\n", 6, 0}},
		{curlCase("curl", "http://nosuch.invalid/"),
			stubWant{"", curlMeterHead + curlMeterZero + "curl: (6) Could not resolve host: nosuch.invalid\n", 6, 0}},
		{curlCase("curl", "-sS", "-o", "/tmp/x", "http://127.0.0.1:1/"), stubWant{"", refused, 7, 0}},
		{curlCase("curl", "-sSo/dev/null", u+"/ok"), stubWant{"", "", 0, 0}},
		{curlCase("curl", "-ms3", "http://10.66.0.5/"),
			stubWant{"", "curl: option -ms3: expected a proper numerical parameter\n" + curlTry, 2, 0}},
		{curlCase("curl", "-sS", "-m", "-1", u+"/ok"),
			stubWant{"", "curl: option -m: expected a proper numerical parameter\n" + curlTry, 2, 0}},
		{curlCase("curl", "-sS", "--retry", "-1", u+"/ok"),
			stubWant{"", "curl: option --retry: expected a positive numerical parameter\n" + curlTry, 2, 0}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		checkStub(t, argvLabel(c.c), got[i], c.want)
	}
}

// TestCurlMeterAndRetries: the parts of curl's output that are not the same
// on every run (the meter's seconds) are checked piece by piece.
func TestCurlMeterAndRetries(t *testing.T) {
	u := "http://" + curlHTTP
	got := runCowrieStub(t, []stubCase{
		curlCase("curl", "-m", "3", "--retry", "1", "http://10.66.0.5/ping/x"),
		curlCase("curl", "-f", u+"/missing"),
		curlCase("curl", "-o", "/nonexist/dir/f", u+"/ok"),
		curlCase("curl", "-O", u+"/ok"),
		curlCase("curl", "-I", u+"/ok"),
		curlCase("curl", "-fI", u+"/missing"),
	})
	retry := got[0].Stderr
	if !strings.HasPrefix(retry, curlMeterHead) || strings.Count(retry, "curl: (28) Connection timed out after ") != 2 ||
		!strings.Contains(retry, "\nWarning: Problem : timeout. Will retry in 1 second. 1 retry left.\n") ||
		!strings.Contains(retry, " 0:00:01 ") || got[0].code() != 28 || got[0].Seconds != 7 {
		t.Errorf("-m 3 --retry 1: %d after %.1f s, %q", got[0].code(), got[0].Seconds, retry)
	}
	if e := got[1].Stderr; e != curlMeterHead+curlMeterZero+curlMeterZero+"\ncurl: (22) The requested URL returned error: 404\n" ||
		got[1].code() != 22 || got[1].Stdout != "" {
		t.Errorf("-f 404: %d %q %q", got[1].code(), got[1].Stdout, e)
	}
	if e := got[2].Stderr; e != curlMeterHead+curlMeterZero+"Warning: Failed to open the file /nonexist/dir/f: No such file or directory\n"+
		"\r  0     6    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0\n"+
		"curl: (23) client returned ERROR on write of 6 bytes\n" || got[2].code() != 23 {
		t.Errorf("-o in a missing folder: %d %q", got[2].code(), e)
	}
	// the meter's last line: everything received, at some speed
	done := regexp.MustCompile(`^\r100     6  100     6    0     0  [ 0-9]{4}[0-9kM]      0 --:--:-- --:--:-- --:--:-- [ 0-9.]{4}[0-9kM]\n$`)
	saved := false
	for _, e := range got[3].Events {
		saved = saved || e["eventid"] == "cowrie.session.file_download" && e["outfile"] == "/root/ok"
	}
	if !saved || got[3].code() != 0 || got[3].Stdout != "" || !strings.HasPrefix(got[3].Stderr, curlMeterHead+curlMeterZero) ||
		!done.MatchString(strings.TrimPrefix(got[3].Stderr, curlMeterHead+curlMeterZero)) {
		t.Errorf("-O: %d, events %v, out %q err %q", got[3].code(), got[3].Events, got[3].Stdout, got[3].Stderr)
	}
	if o := got[4].Stdout; !strings.HasPrefix(o, "HTTP/1.1 200 OK\r\n") || !strings.HasSuffix(o, "\r\n\r\n") || got[4].code() != 0 ||
		strings.Contains(o, "hello") || got[4].Stderr != curlMeterHead+curlMeterZero+
		"\r  0     6    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0\n" {
		t.Errorf("-I: %d %q %q", got[4].code(), o, got[4].Stderr)
	}
	if o := got[5].Stdout; !strings.HasPrefix(o, "HTTP/1.1 404 Not Found\r\n") || got[5].code() != 22 ||
		!strings.HasSuffix(got[5].Stderr, "curl: (22) The requested URL returned error: 404\n") {
		t.Errorf("-fI: %d %q %q", got[5].code(), o, got[5].Stderr)
	}
	for _, r := range got {
		for _, f := range r.Fetches {
			if f.Method == "head" && !strings.HasSuffix(f.URL, "/ok") && !strings.HasSuffix(f.URL, "/missing") {
				t.Errorf("HEAD of %s", f.URL)
			}
		}
	}
}

// onTerminal is a case whose output is the terminal: curl draws no meter.
func onTerminal(c stubCase) stubCase {
	c["terminal"] = true
	return c
}

// TestCurlReleases: the messages of the persona's own curl, from its
// release's sources (connect.c, multi.c, tool_operate.c, tool_msgs.c).
func TestCurlReleases(t *testing.T) {
	persona := func(p string, argv ...string) stubCase {
		c := curlCase(argv...)
		c["persona"] = p
		return c
	}
	cases := []struct {
		c    stubCase
		want stubWant
	}{
		{persona("ubuntu-24.04", "curl", "-sS", "http://127.0.0.1:1/"),
			stubWant{"", "curl: (7) Failed to connect to 127.0.0.1 port 1 after 0 ms: Couldn't connect to server\n", 7, 0}},
		{persona("ubuntu-24.04", "curl", "-sS", "http://10.66.0.5/"),
			stubWant{"", "curl: (28) Failed to connect to 10.66.0.5 port 80 after 127120 ms: Couldn't connect to server\n", 28, 127}},
		{onTerminal(persona("ubuntu-24.04", "curl", "-m", "2", "--retry", "1", "http://10.66.0.5/")),
			stubWant{"", "curl: (28) Connection timed out after 2001 milliseconds\n" +
				"Warning: Problem : timeout. Will retry in 1 seconds. 1 retries left.\n" +
				"curl: (28) Connection timed out after 2001 milliseconds\n", 28, 5}},
		{persona("ubuntu-22.04", "curl", "-sS", "http://127.0.0.1:1/"),
			stubWant{"", "curl: (7) Failed to connect to 127.0.0.1 port 1 after 0 ms: Connection refused\n", 7, 0}},
		{persona("ubuntu-22.04", "curl", "-sS", "http://10.66.0.5/"),
			stubWant{"", "curl: (28) Failed to connect to 10.66.0.5 port 80 after 127120 ms: Connection timed out\n", 28, 127}},
		{persona("ubuntu-22.04", "curl", "-s"), stubWant{"", "curl: no URL specified!\n" + curlTry, 2, 0}},
		{persona("debian-12", "curl", "-sS", "http://127.0.0.1:1/"),
			stubWant{"", "curl: (7) Failed to connect to 127.0.0.1 port 1 after 0 ms: Couldn't connect to server\n", 7, 0}},
		{persona("rhel-9", "curl", "-sS", "http://127.0.0.1:1/"),
			stubWant{"", "curl: (7) Failed to connect to 127.0.0.1 port 1: Connection refused\n", 7, 0}},
		{persona("rhel-9", "curl", "-sS", "http://10.66.0.5/"),
			stubWant{"", "curl: (28) Failed to connect to 10.66.0.5 port 80: Connection timed out\n", 28, 127}},
		{persona("centos-7", "curl", "-sS", "http://127.0.0.1:1/"),
			stubWant{"", "curl: (7) Failed connect to 127.0.0.1:1; Connection refused\n", 7, 0}},
		{persona("centos-7", "curl", "-sS", "http://10.66.0.5/"),
			stubWant{"", "curl: (7) Failed connect to 10.66.0.5:80; Connection timed out\n", 7, 127}},
		{persona("centos-7", "curl", "-sS", "http://nosuch.invalid/"),
			stubWant{"", "curl: (6) Could not resolve host: nosuch.invalid; Unknown error\n", 6, 0}},
		{onTerminal(persona("centos-7", "curl", "-m", "1", "--retry", "1", "http://10.66.0.5/")),
			stubWant{"", "curl: (28) Connection timed out after 1001 milliseconds\n" +
				"Warning: Transient problem: timeout Will retry in 1 seconds. 1 retries left.\n" +
				"curl: (28) Connection timed out after 1001 milliseconds\n", 28, 3}},
		{persona("centos-7", "curl", "-sSf", "http://"+curlHTTP+"/missing"),
			stubWant{"", "curl: (22) The requested URL returned error: 404 Not Found\n", 22, 0}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		checkStub(t, c.c["persona"].(string)+": "+argvLabel(c.c), got[i], c.want)
	}
	// curl --version: the persona's build, its Debian package's patch stamp
	v := curlCase("curl", "--version")
	v["packages"] = map[string]string{"curl": "8.14.1-2+deb13u3"}
	v["config"] = map[string]any{"shell.ssh_version": "OpenSSH_10.0p2 Debian-7, OpenSSL 3.5.6 4 Nov 2025"}
	ver := runCowrieStub(t, []stubCase{v})[0]
	want := "curl 8.14.1 (x86_64-pc-linux-gnu) libcurl/8.14.1 OpenSSL/3.5.6 zlib/1.3.1 brotli/1.1.0 zstd/1.5.7 libidn2/2.3.8 " +
		"libpsl/0.21.2 libssh2/1.11.1 nghttp2/1.64.0 nghttp3/1.8.0 librtmp/2.3 OpenLDAP/2.6.10\n" +
		"Release-Date: 2025-06-04, security patched: 8.14.1-2+deb13u3\n" +
		"Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns ldap ldaps mqtt pop3 pop3s rtmp rtsp scp " +
		"sftp smb smbs smtp smtps telnet tftp ws wss\n" +
		"Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL SPNEGO " +
		"SSL threadsafe TLS-SRP UnixSockets zstd\n"
	if ver.Stdout != want || ver.code() != 0 {
		t.Errorf("curl --version:\n%q\nwant\n%q", ver.Stdout, want)
	}
}

// wgetUsage follows each of GNU wget's option errors.
const wgetUsage = "Usage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n"

// wgetDate is the time stamp of each of GNU wget's tries.
var wgetDate = regexp.MustCompile(`--[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}--`)

// TestWgetLikeWget: GNU wget 1.25.0's tries, waits and statuses at an
// address that refuses or never answers, and its option errors.
func TestWgetLikeWget(t *testing.T) {
	timedOut := "Connecting to 10.66.0.5:80... failed: Connection timed out.\n"
	cases := []struct {
		c    stubCase
		want stubWant
	}{
		{curlCase("wget", "http://127.0.0.1:1/"),
			stubWant{"", "--D--  http://127.0.0.1:1/\nConnecting to 127.0.0.1:1... failed: Connection refused.\n", 4, 0}},
		{curlCase("wget", "-q", "http://127.0.0.1:1/"), stubWant{"", "", 4, 0}},
		{curlCase("wget", "-T", "2", "-t", "2", "http://10.66.0.5/x"),
			stubWant{"", "--D--  http://10.66.0.5/x\n" + timedOut + "Retrying.\n\n--D--  (try: 2)  http://10.66.0.5/x\n" +
				timedOut + "Giving up.\n\n", 4, 5}},
		{curlCase("wget", "-t", "1", "http://10.66.0.5/x"),
			stubWant{"", "--D--  http://10.66.0.5/x\n" + timedOut + "Giving up.\n\n", 4, 127}},
		{curlCase("wget", "-q", "-T", "2", "-t", "1", "http://10.66.0.5/x"), stubWant{"", "", 4, 2}},
		// -T longer than the kernel's wait: the kernel gives up first (recorded: -T 20 failed after 7 s)
		{curlCase("wget", "-T", "200", "-t", "1", "http://10.66.0.5/x"),
			stubWant{"", "--D--  http://10.66.0.5/x\n" + timedOut + "Giving up.\n\n", 4, 127}},
		{curlCase("wget", "http://nosuch.invalid/"),
			stubWant{"", "--D--  http://nosuch.invalid/\nResolving nosuch.invalid (nosuch.invalid)... failed: " +
				"Name or service not known.\nwget: unable to resolve host address ‘nosuch.invalid’\n", 4, 0}},
		{curlCase("wget", "-Z", "http://x/"), stubWant{"", "wget: invalid option -- 'Z'\n" + wgetUsage, 2, 0}},
		{curlCase("wget", "--nope", "http://x/"), stubWant{"", "wget: unrecognized option '--nope'\n" + wgetUsage, 2, 0}},
		{curlCase("wget", "-T"), stubWant{"", "wget: option requires an argument -- 'T'\n" + wgetUsage, 2, 0}},
		{curlCase("wget", "--tries"), stubWant{"", "wget: option '--tries' requires an argument\n" + wgetUsage, 2, 0}},
		{curlCase("wget"), stubWant{"", "wget: missing URL\n" + wgetUsage, 1, 0}},
		{curlCase("wget", "-T", "x", "http://127.0.0.1:1/"),
			stubWant{"", "wget: --timeout: Invalid time period ‘x’\n", 2, 0}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		got[i].Stderr = wgetDate.ReplaceAllString(got[i].Stderr, "--D--")
		checkStub(t, argvLabel(c.c), got[i], c.want)
	}
}

// TestCurlWgetNoNewEgress: whatever the arguments, curl and wget reach the
// network no more than Cowrie's own did: at most one lookup of a name (none
// of an address, a bait host or a name of /etc/hosts), at most one fetch,
// GET or HEAD with the stock user agent and no redirects, never a fetch of
// an address the honeypot does not contact. Random command lines, bounded.
func TestCurlWgetNoNewEgress(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	hosts := []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "monitor", "db01", "[::1]", "0.0.0.0",
		curlHTTP, "93.184.215.14", "example.com", "nosuch.invalid", "localhost", "web01", "100.64.0.1", "[fe80::1]"}
	paths := []string{"/ok", "/missing", "/x", "/redir", "/unavail", "/" + strings.Repeat("a", 300)}
	opts := [][]string{{"-s"}, {"-S"}, {"-f"}, {"-L"}, {"-k"}, {"-I"}, {"-m", "2"}, {"--retry", "3"}, {"--retry-delay", "0"},
		{"--retry-connrefused"}, {"--retry-all-errors"}, {"-o", "/tmp/o"}, {"-O"}, {"-w", "%{http_code}"}, {"-H", "Host: x"},
		{"-X", "POST"}, {"-d", "x"}, {"-x", "http://10.0.0.9:3128"}, {"--connect-timeout", "1"}, {"-A", "evil"},
		{"--resolve", "x:80:10.0.0.1"}, {"-T", "1"}, {"-t", "2"}, {"--tries=3"}, {"-q"}, {"-O", "-"}, {"--header=X: y"}}
	plan := map[string]any{"hosts": []map[string]any{{"ip": "10.158.124.191", "names": []string{"monitor"}},
		{"ip": "10.158.124.18", "names": []string{"db01"}}}}
	var cases []stubCase
	for i := 0; i < 300; i++ {
		prog := []string{"curl", "wget"}[rng.Intn(2)]
		argv := []string{prog}
		for j := rng.Intn(5); j > 0; j-- {
			argv = append(argv, opts[rng.Intn(len(opts))]...)
		}
		scheme := []string{"http://", "https://", "", "ftp://"}[rng.Intn(4)]
		for j := 1 + rng.Intn(2); j > 0; j-- {
			argv = append(argv, scheme+hosts[rng.Intn(len(hosts))]+paths[rng.Intn(len(paths))])
		}
		c := curlCase(argv...)
		c["plan"] = plan
		c["dns"] = map[string]any{"example.com": "93.184.215.14", "nosuch.invalid": nil}
		c["files"].(map[string]any)["/etc/hosts"] = "127.0.0.1 localhost\n10.20.0.5 web01\n"
		cases = append(cases, c)
	}
	start := time.Now()
	got := runCowrieStub(t, cases)
	elapsed := time.Since(start)
	worst := 0.0
	for i, r := range got {
		label := argvLabel(cases[i])
		if r.CPU > worst {
			worst = r.CPU
		}
		if len(r.Fetches) > 1 || len(r.Lookups) > 1 {
			t.Errorf("%s: %d fetches, %d lookups", label, len(r.Fetches), len(r.Lookups))
		}
		// a name is looked up once, as Cowrie did; never an address, a bait host or a name of /etc/hosts
		for _, name := range r.Lookups {
			if net.ParseIP(strings.Trim(name, "[]")) != nil || name == "localhost" || name == "web01" || name == "monitor" ||
				name == "db01" || strings.Contains(name, "93.184.215.14") {
				t.Errorf("%s: looked up %q", label, name)
			}
		}
		for _, f := range r.Fetches {
			if (f.Method != "get" && f.Method != "head" && f.Method != "") || f.MaxRedirects > 0 && strings.HasPrefix(label, "curl") ||
				f.Timeout > 10 {
				t.Errorf("%s: fetch %+v", label, f)
			}
			if !strings.Contains(f.URL, "93.184.215.14") && !strings.Contains(f.URL, "example.com") {
				t.Errorf("%s: fetched %s", label, f.URL)
			}
			for k, v := range f.Headers {
				if !strings.EqualFold(k, "User-Agent") || len(v) != 1 || strings.Contains(v[0], "evil") {
					t.Errorf("%s: header %s %v", label, k, v)
				}
			}
		}
		if !r.Exited && r.code() < 0 {
			t.Errorf("%s: never exited", label)
		}
	}
	if worst > 0.25 {
		t.Errorf("one command line took %.3f s of CPU", worst)
	}
	t.Logf("300 command lines in %v, worst %.4f s CPU", elapsed, worst)
}

// egressCase is a curl or wget command line whose names the persona's
// /etc/hosts and its DNS answer differently: evil.example is public in
// /etc/hosts and link-local in the DNS; rebind.example's DNS answers public,
// then link-local (a rebinding server).
func egressCase(argv ...string) stubCase {
	c := curlCase(argv...)
	c["files"].(map[string]any)["/etc/hosts"] = "127.0.0.1 localhost\n93.184.215.20 evil.example\n"
	c["dns"] = map[string]any{"evil.example": "169.254.169.254", "rebind.example": []string{"93.184.215.21", "169.254.169.254"},
		"example.com": "93.184.215.14"}
	page := map[string]any{"code": 200, "phrase": "OK", "body": "hi\n"}
	c["http"] = map[string]any{"http://evil.example/x": page, "http://rebind.example/x": page, "http://example.com/x": page}
	return c
}

// busybox makes a case BusyBox's wget (an ash persona).
func busybox(c stubCase) stubCase {
	c["config"] = map[string]any{"shell.wget_style": "busybox", "shell.text_version": "1.36.1", "shell.not_found_style": "ash"}
	return c
}

// TestCurlWgetConnectOnlyToChecked: curl and wget connect to the very
// address they checked, never to what a second lookup of the name answers:
// a name of /etc/hosts goes to its address there and is never looked up; a
// name the DNS answers is looked up once and connected to at that answer,
// whatever a later lookup says; FTP's control and data connections both go
// there, whatever host the server's PASV answer names.
func TestCurlWgetConnectOnlyToChecked(t *testing.T) {
	cases := []struct {
		c       stubCase
		address string
		lookups int
		ports   []int
	}{
		{egressCase("curl", "-s", "http://evil.example/x"), "93.184.215.20", 0, []int{0}},
		{egressCase("curl", "-sI", "http://evil.example/x"), "93.184.215.20", 0, []int{0}},
		{egressCase("wget", "-q", "-O-", "http://evil.example/x"), "93.184.215.20", 0, []int{0}},
		{egressCase("curl", "-s", "http://rebind.example/x"), "93.184.215.21", 1, []int{0}},
		{egressCase("wget", "-q", "-O-", "http://rebind.example/x"), "93.184.215.21", 1, []int{0}},
		{busybox(egressCase("wget", "-O-", "http://rebind.example/x")), "93.184.215.21", 1, []int{0}},
		{egressCase("curl", "-s", "http://example.com/x"), "93.184.215.14", 1, []int{0}},
		{egressCase("wget", "ftp://evil.example/pub/f"), "93.184.215.20", 0, []int{21, 2121}},
		{egressCase("wget", "ftp://rebind.example/pub/f"), "93.184.215.21", 1, []int{21, 2121}},
		{busybox(egressCase("wget", "ftp://rebind.example/f")), "93.184.215.21", 1, []int{21, 2121}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		r, label := got[i], argvLabel(c.c)
		if len(r.Lookups) != c.lookups {
			t.Errorf("%s: looked up %v, want %d lookup(s)", label, r.Lookups, c.lookups)
		}
		var ports []int
		for _, conn := range r.Connects {
			if conn.Host != c.address {
				t.Errorf("%s: connected to %s:%d, want only %s", label, conn.Host, conn.Port, c.address)
			}
			ports = append(ports, conn.Port)
		}
		if fmt.Sprint(ports) != fmt.Sprint(c.ports) {
			t.Errorf("%s: connections on ports %v, want %v (out %q err %q)", label, ports, c.ports, r.Stdout, r.Stderr)
		}
		for _, f := range r.Fetches {
			if f.Address != c.address || f.MaxRedirects != 0 {
				t.Errorf("%s: fetch %+v", label, f)
			}
		}
		if !r.Exited {
			t.Errorf("%s: never exited", label)
		}
	}
}

// TestClassifyCoversCowriesBlocklist: an address the patch layer connects to
// ("network") is one the image's own blocklist (resolve_allowed's, the stub's
// verbatim copy) lets through, for the metadata, private, CGNAT, loopback and
// IPv6 wrapper addresses and thousands of random ones; Azure's WireServer is
// blocked as well.
func TestClassifyCoversCowriesBlocklist(t *testing.T) {
	want := map[string]string{
		"169.254.169.254": "timeout", "169.254.170.2": "timeout", "100.100.100.200": "timeout", "168.63.129.16": "timeout",
		"::ffff:168.63.129.16": "timeout", "fd00:ec2::254": "timeout", "fe80::a9fe:a9fe": "timeout",
		"::ffff:169.254.169.254": "timeout", "::ffff:10.0.0.1": "timeout", "64:ff9b::a9fe:a9fe": "timeout",
		"2002:a9fe:a9fe::1": "timeout", "::a9fe:a9fe": "timeout", "10.1.2.3": "timeout", "172.17.0.1": "timeout",
		"192.168.1.1": "timeout", "100.64.0.1": "timeout", "100.127.255.254": "timeout", "224.0.0.251": "timeout",
		"255.255.255.255": "timeout", "240.0.0.1": "timeout", "192.0.2.1": "timeout", "198.18.0.1": "timeout",
		"ff02::1": "timeout", "127.0.0.1": "refused", "127.1.2.3": "refused", "::1": "refused", "0.0.0.0": "refused",
		"::": "refused", "93.184.215.14": "network", "8.8.8.8": "network", "1.1.1.1": "network",
		"2606:4700:4700::1111": "network", "168.63.129.17": "network",
	}
	rng := rand.New(rand.NewSource(5))
	var addresses []string
	for a := range want {
		addresses = append(addresses, a)
	}
	addresses = append(addresses, "::ffff:127.0.0.1")
	for i := 0; i < 3000; i++ {
		b := make([]byte, 16)
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		v4 := net.IP(b[:4]).String()
		switch i % 4 {
		case 0:
			addresses = append(addresses, v4)
		case 1:
			addresses = append(addresses, "::ffff:"+v4)
		case 2:
			addresses = append(addresses, net.IP(b).String())
		default:
			addresses = append(addresses, "64:ff9b::"+v4)
		}
	}
	r := runCowrieStub(t, []stubCase{{"probe": "classify", "addresses": addresses, "persona": "debian-13"}})[0]
	var table map[string]struct {
		Kind            string `json:"kind"`
		UpstreamBlocked *bool  `json:"upstream_blocked"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &table); err != nil {
		t.Fatal(err)
	}
	network := 0
	for _, a := range addresses {
		e, ok := table[a]
		if !ok || e.UpstreamBlocked == nil {
			t.Fatalf("%s: no answer", a)
		}
		if w, ok := want[a]; ok && e.Kind != w {
			t.Errorf("%s: %s, want %s", a, e.Kind, w)
		}
		if e.Kind == "network" {
			network++
			if *e.UpstreamBlocked {
				t.Errorf("%s: connected to, though Cowrie's blocklist blocks it", a)
			}
		}
		if *e.UpstreamBlocked && e.Kind == "network" || e.Kind == "" {
			t.Errorf("%s: %+v", a, e)
		}
	}
	if network < 500 {
		t.Errorf("only %d of %d addresses public: the random ones are not random", network, len(addresses))
	}
}

// TestFetchChecksItsAddress: qpot_fetch sends nothing to an address the
// honeypot does not contact, whatever its caller passes, and nothing to IPv6
// (the outbound address is an IPv4 one); a public address gets the request,
// to that address and not to the URL's name.
func TestFetchChecksItsAddress(t *testing.T) {
	calls := [][]string{
		{"http://evil.example/x", "169.254.169.254"}, {"http://evil.example/x", "127.0.0.1"},
		{"http://evil.example/x", "::ffff:10.0.0.1"}, {"http://evil.example/x", "168.63.129.16"},
		{"http://evil.example/x", "evil.example"}, {"http://evil.example/x", ""},
		{"http://evil.example/x", "2606:4700:4700::1111"}, {"https://evil.example/x", "93.184.215.20"},
	}
	r := runCowrieStub(t, []stubCase{{"probe": "qpot_fetch", "fetch_calls": calls, "persona": "debian-13"}})[0]
	var outcomes []string
	if err := json.Unmarshal([]byte(r.Stdout), &outcomes); err != nil {
		t.Fatal(err)
	}
	want := "BlockedAddress BlockedAddress BlockedAddress BlockedAddress BlockedAddress BlockedAddress " +
		"UnreachableAddress sent 93.184.215.20"
	if strings.Join(outcomes, " ") != want || len(r.Lookups) != 0 || len(r.Connects) != 1 || r.Connects[0].Host != "93.184.215.20" {
		t.Errorf("qpot_fetch: %v, lookups %v, connects %v", outcomes, r.Lookups, r.Connects)
	}
}
