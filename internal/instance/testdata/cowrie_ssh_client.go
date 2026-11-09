// Command cowrie_ssh_client checks action consequences over real local SSH.
// It runs only inside the test container's network-none namespace.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	var pinned []byte
	config := &ssh.ClientConfig{
		User: "root", Auth: []ssh.AuthMethod{ssh.Password("local-test-only")}, Timeout: 5 * time.Second,
		HostKeyCallback: func(_ string, remote net.Addr, key ssh.PublicKey) error {
			host, _, err := net.SplitHostPort(remote.String())
			if err != nil || !net.ParseIP(host).IsLoopback() {
				return fmt.Errorf("test SSH endpoint must be loopback")
			}
			if pinned == nil {
				pinned = append([]byte(nil), key.Marshal()...)
			} else if !bytes.Equal(pinned, key.Marshal()) {
				return fmt.Errorf("test service host key changed")
			}
			return nil
		},
	}
	connect := func(user, local string) *ssh.Client {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		if local != "" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
		}
		conn, err := dialer.Dial("tcp", "127.0.0.1:22")
		must(err)
		must(conn.SetDeadline(time.Now().Add(90 * time.Second)))
		actorConfig := *config
		actorConfig.User = user
		client, channels, requests, err := ssh.NewClientConn(conn, "127.0.0.1:22", &actorConfig)
		must(err)
		return ssh.NewClient(client, channels, requests)
	}
	first := connect("root", "")
	defer first.Close()
	run := func(client *ssh.Client, command string, status int) string {
		session, err := client.NewSession()
		if err != nil {
			fail("new channel for %q: %v", command, err)
		}
		defer session.Close()
		output, err := session.CombinedOutput(command)
		actual := 0
		if exit, ok := err.(*ssh.ExitError); ok {
			actual = exit.ExitStatus()
		} else {
			if err != nil {
				fail("execute %q: %v (output %q)", command, err, output)
			}
		}
		if actual != status {
			fail("%q: expected exit%d, got%d: %s", command, status, actual, output)
		}
		return strings.TrimSpace(string(output))
	}
	checks := []string{}
	uts := newSFTP(first)
	defer uts.session.Close()
	utsHandle := handle(uts.request(3, str("/proc/sys/kernel/hostname"), u32(1), u32(0)))
	readUTS := func(want string) {
		response := uts.request(5, str(utsHandle), make([]byte, 8), u32(1024))
		if len(response) < 9 || response[0] != 103 || string(response[9:]) != want+"\n" {
			fail("SFTP virtual hostname expected %q: %q", want, response)
		}
	}
	original := run(first, "hostname", 0)
	readUTS(original)
	for _, field := range []struct{ name, flag string }{{"ostype", "-s"}, {"osrelease", "-r"}, {"version", "-v"}} {
		want := run(first, "uname "+field.flag, 0)
		if got := run(first, "cat /proc/sys/kernel/"+field.name, 0); got != want {
			fail("virtual UTS %s disagrees with uname: %q != %q", field.name, got, want)
		}
	}
	before := run(first, "sha256sum /bin/bash", 0)
	run(first, "hostname maintenance01", 0)
	if got := run(first, "hostname; uname -n", 0); got != "maintenance01\nmaintenance01" {
		fail("cross-channel hostname/uname mismatch: %q", got)
	}
	if got := run(first, "cat /proc/sys/kernel/hostname", 0); got != "maintenance01" {
		fail("virtual UTS hostname did not follow shell change: %q", got)
	}
	readUTS("maintenance01")
	sftpStatus(uts.request(4, str(utsHandle)), 0)
	checks = append(checks, "SFTP-first UTS metadata matches uname and follows later shell hostname changes")
	meminfo := run(first, "cat /proc/meminfo", 0)
	var totalKiB int64
	for _, line := range strings.Split(meminfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, parseErr := strconv.ParseInt(fields[1], 10, 64)
			must(parseErr)
			totalKiB = value
		}
	}
	for _, unit := range []struct {
		flag    string
		divisor int64
	}{{"-k", 1}, {"-m", 1024}} {
		output := run(first, "free "+unit.flag, 0)
		var total int64
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "Mem:" {
				value, parseErr := strconv.ParseInt(fields[1], 10, 64)
				must(parseErr)
				total = value
			}
		}
		if totalKiB <= 0 || total != totalKiB/unit.divisor {
			fail("free %s differs from /proc/meminfo: %d != %d/%d", unit.flag, total, totalKiB, unit.divisor)
		}
	}
	if got := run(first, "free -q", 1); !strings.Contains(got, "invalid option") {
		fail("free invalid flag did not produce an error: %q", got)
	}
	checks = append(checks, "free KiB/MiB agree with virtual meminfo and invalid flags fail")
	if after := run(first, "sha256sum /bin/bash", 0); after != before {
		fail("hostname changed unchanged file checksum: before%q after%q", before, after)
	}
	checks = append(checks, "hostname/uname shared between SSH exec channels", "unchanged file checksum survives hostname change")
	procBefore := run(first, "cat /proc/version", 0)
	procMode := run(first, "stat -c '%a' /proc/version", 0)
	for _, command := range []string{"echo changed > /proc/version", "echo changed > /proc/validation-new", "mkdir /proc/validation-directory", "rm /proc/version", "chmod 600 /proc/version", "touch /proc/version"} {
		if got := run(first, command, 1); !strings.Contains(got, "Permission denied") && !strings.Contains(got, "Operation not permitted") {
			fail("generated proc mutation failed without realistic denial: %q %q", command, got)
		}
	}
	if got := run(first, "cat /proc/version", 0); got != procBefore {
		fail("denied proc write changed kernel version: %q", got)
	}
	if got := run(first, "stat -c '%a' /proc/version", 0); got != procMode {
		fail("denied proc chmod changed mode: %q", got)
	}
	run(first, "test ! -e /proc/validation-new", 0)
	checks = append(checks, "root proc mutations return permission errors and preserve generated bytes/mode")
	run(first, "printf 'local-state\n' > /tmp/state-proof; chmod 640 /tmp/state-proof", 0)
	if got := run(first, "cat /tmp/state-proof; stat -c '%a' /tmp/state-proof", 0); got != "local-state\n640" {
		fail("file write/chmod missing on subsequent channel: %q", got)
	}
	inode := run(first, "stat -c '%i' /tmp/state-proof", 0)
	run(first, "mv /tmp/state-proof /tmp/renamed-proof", 0)
	if got := run(first, "stat -c '%i' /tmp/renamed-proof", 0); got != inode {
		fail("rename changed inode: %q -> %q", inode, got)
	}
	checks = append(checks, "write/chmod reflected by cat/stat on another channel", "rename preserves inode")
	beforeTouch, parseErr := strconv.ParseInt(run(first, "stat -c '%Y' /etc/hostname", 0), 10, 64)
	must(parseErr)
	run(first, "touch /etc/hostname", 0)
	afterTouch, parseErr := strconv.ParseInt(run(first, "stat -c '%Y' /etc/hostname", 0), 10, 64)
	must(parseErr)
	if afterTouch <= beforeTouch {
		fail("plain touch did not advance baseline file mtime: %d -> %d", beforeTouch, afterTouch)
	}
	checks = append(checks, "plain touch advances existing baseline file mtime across channels")
	if got := run(first, "touch /tmp/renamed-proof/", 1); !strings.Contains(got, "Not a directory") {
		fail("touch lost existing trailing-slash semantics: %q", got)
	}
	run(first, "printf A > /tmp/same-name; mv /tmp/same-name /tmp/first-name; printf B > /tmp/same-name", 0)
	if got := run(first, "cat /tmp/first-name; cat /tmp/same-name", 0); got != "AB" {
		fail("two artifacts sharing an earlier virtual name became conflated: %q", got)
	}
	fileHash := strings.Fields(run(first, "sha256sum /tmp/first-name", 0))[0]
	streamHash := strings.Fields(run(first, "cat /tmp/first-name | sha256sum", 0))[0]
	if fileHash != streamHash {
		fail("cat changed file bytes: %s != %s", fileHash, streamHash)
	}
	if got := run(first, "cat < /tmp/first-name", 0); got != "A" {
		fail("readable stdin redirection failed: %q", got)
	}
	run(first, "printf first > /tmp/copy-a; printf first > /tmp/copy-b", 0)
	run(first, "printf second >> /tmp/copy-a", 0)
	if got := run(first, "cat /tmp/copy-a; cat /tmp/copy-b", 0); got != "firstsecondfirst" {
		fail("append changed a previously captured identical artifact: %q", got)
	}
	writerA, err := first.NewSession()
	must(err)
	defer writerA.Close()
	must(writerA.Start("printf one > /tmp/overlap; sleep 1"))
	writerB, err := first.NewSession()
	must(err)
	defer writerB.Close()
	must(writerB.Start("{ printf two; sleep 2; printf three; } >> /tmp/overlap"))
	must(writerA.Wait())
	must(writerB.Wait())
	if got := run(first, "cat /tmp/overlap; stat -c '%s' /tmp/overlap", 0); got != "onetwothree11" {
		fail("overlapping writer finalization lost data: %q", got)
	}
	checks = append(checks, "same-name artifact versions remain distinct", "append preserves earlier identical captures", "overlapping SSH channel writers retain bytes and size after first channel closes")
	run(first, "useradd -m -u 23456 -G root -s /bin/bash analystqa", 0)
	if got := run(first, "id analystqa; getent passwd analystqa", 0); !strings.Contains(got, "uid=23456(analystqa)") || !strings.Contains(got, "/home/analystqa:/bin/bash") {
		fail("new account not visible to id/getent: %q", got)
	}
	run(first, "chown analystqa:analystqa /tmp/renamed-proof", 0)
	if got := run(first, "stat -c '%u:%U:%g:%G' /tmp/renamed-proof", 0); got != "23456:analystqa:23456:analystqa" {
		fail("new owner not reflected by stat: %q", got)
	}
	if got := run(first, "su -c 'id -un' analystqa", 0); got != "analystqa" {
		fail("su cannot resolve new account: %q", got)
	}
	checks = append(checks, "useradd changes passwd/id/getent and su", "chown resolves newly created owner")
	run(first, "printf 'root-only-v1\\n' > /tmp/root-only; chmod 600 /tmp/root-only", 0)
	if got := run(first, "su -c 'cat /tmp/root-only' analystqa", 1); !strings.Contains(got, "Permission denied") {
		fail("su read denial missing: %q", got)
	}
	run(first, "su -c 'chmod 777 /tmp/root-only' analystqa", 1)
	run(first, "su -c 'echo overwrite > /tmp/root-only' analystqa", 1)
	if got := run(first, "cat /tmp/root-only; stat -c '%a' /tmp/root-only", 0); got != "root-only-v1\n600" {
		fail("denied write/chmod altered original: %q", got)
	}
	if got := run(first, "sudo -u analystqa id -un", 0); got != "analystqa" {
		fail("sudo target ignored: %q", got)
	}
	run(first, "sudo -u analystqa cat /tmp/root-only", 1)
	run(first, "sudo -u analystqa cp /tmp/root-only /tmp/forbidden-copy", 1)
	run(first, "sudo -u analystqa rm /tmp/root-only", 1)
	run(first, "test ! -e /tmp/forbidden-copy", 0)
	if got := run(first, "sudo -u analystqa cp /tmp/renamed-proof /tmp/actor-copy; stat -c '%u' /tmp/actor-copy", 0); got != "23456" {
		fail("sudo target cp owner mismatch: %q", got)
	}
	run(first, "mkdir /tmp/rmdir-proof; rmdir /tmp/rmdir-proof; test ! -e /tmp/rmdir-proof", 0)
	if got := run(first, "id -un", 0); got != "root" {
		fail("sudo mutated login: %q", got)
	}
	checks = append(checks, "su/sudo target cannot read/write/chmod another owner's 0600 file", "denied redirect preserves bytes and channel; sudo does not mutate login")
	sftp := newSFTP(first)
	defer sftp.session.Close()
	sftp.writeDenied("/proc/version")
	// Opening another subsystem must retain the exact connection filesystem.
	if got := run(first, "cat /tmp/renamed-proof", 0); got != "local-state" {
		fail("SFTP reset exec state: %q", got)
	}
	sftp.write("/tmp/sftp-proof", []byte("sftp-state\n"), 0640)
	if got := run(first, "cat /tmp/sftp-proof; stat -c '%a' /tmp/sftp-proof", 0); got != "sftp-state\n640" {
		fail("SFTP bytes/mode missing from exec: %q", got)
	}
	sftp.directory("/home/analystqa", "analystqa")
	sftp.renameFailure("/tmp/renamed-proof", "/missing-parent/destination")
	sftp.sharedInode(first, run)
	if got := run(first, "cat /tmp/renamed-proof", 0); got != "local-state" {
		fail("failed SFTP rename lost source: %q", got)
	}
	checks = append(checks, "SFTP and exec share filesystem, upload bytes and mode", "SFTP lists new account owner and fstat works", "failed SFTP rename preserves source")
	checks = append(checks, "active rmdir works and cp respects nonowner read permissions", "SFTP overlapping descriptors share bytes/live reads/fstat through rename/unlink/recreate and quota rejection")
	run(first, "apt-get remove -y curl", 0)
	run(first, "which curl", 1)
	run(first, "apt-get install -y curl", 0)
	if got := run(first, "curl --version", 0); !strings.HasPrefix(got, "curl ") {
		fail("reinstalled curl unavailable in later channel: %q", got)
	}
	checks = append(checks, "apt removal/reinstall affects later command resolution")
	second := connect("root", "")
	defer second.Close()
	if got := run(second, "hostname", 0); got != original {
		fail("unrelated connection inherited runtime hostname: %q", got)
	}
	if got := run(second, "cat /proc/sys/kernel/hostname", 0); got != original {
		fail("unrelated connection inherited UTS hostname: %q", got)
	}
	run(second, "test ! -e /tmp/renamed-proof", 0)
	run(second, "getent passwd analystqa", 2)
	checks = append(checks, "unrelated connection has pristine filesystem/accounts/hostname", "stable SSH host key across connections")
	nonroot := connect("debian", "127.0.0.2")
	defer nonroot.Close()
	run(nonroot, "cat /etc/shadow", 1)
	newSFTP(nonroot).readDenied("/etc/shadow")
	if got := run(nonroot, "id -un", 0); got != "debian" {
		fail("channel unusable after SFTP denial: %q", got)
	}
	checks = append(checks, "nonroot SSH and SFTP deny shadow reads and preserve usable connection")
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"result": "PASS", "checks": checks,
		"scope": "real SSH protocol to loopback inside network-none test container"}))
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// A bounded SFTP v3 client for the handful of wire operations under test.
// Keeping it here avoids substituting an adapter for the actual subsystem.
type sftpProbe struct {
	session *ssh.Session
	in      io.WriteCloser
	out     io.Reader
	id      uint32
}

func u32(value uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, value); return b }
func str(value string) []byte { return append(u32(uint32(len(value))), []byte(value)...) }
func packet(kind byte, fields ...[]byte) []byte {
	payload := []byte{kind}
	for _, field := range fields {
		payload = append(payload, field...)
	}
	return append(u32(uint32(len(payload))), payload...)
}
func newSFTP(client *ssh.Client) *sftpProbe {
	session, err := client.NewSession()
	must(err)
	input, err := session.StdinPipe()
	must(err)
	output, err := session.StdoutPipe()
	must(err)
	must(session.RequestSubsystem("sftp"))
	p := &sftpProbe{session: session, in: input, out: output}
	_, err = input.Write(packet(1, u32(3)))
	must(err)
	response := p.receive()
	if response[0] != 2 {
		fail("SFTP version response: %v", response)
	}
	return p
}
func (p *sftpProbe) receive() []byte {
	size := make([]byte, 4)
	_, err := io.ReadFull(p.out, size)
	must(err)
	n := binary.BigEndian.Uint32(size)
	if n < 1 || n > 1<<20 {
		fail("invalid SFTP packet length%d", n)
	}
	payload := make([]byte, n)
	_, err = io.ReadFull(p.out, payload)
	must(err)
	return payload
}
func (p *sftpProbe) request(kind byte, fields ...[]byte) []byte {
	p.id++
	fields = append([][]byte{u32(p.id)}, fields...)
	_, err := p.in.Write(packet(kind, fields...))
	must(err)
	response := p.receive()
	if len(response) < 5 || binary.BigEndian.Uint32(response[1:5]) != p.id {
		fail("SFTP response ID mismatch: %v", response)
	}
	return response
}
func sftpStatus(response []byte, code uint32) {
	if len(response) < 9 || response[0] != 101 || binary.BigEndian.Uint32(response[5:9]) != code {
		fail("SFTP expected status%d: %q", code, response)
	}
}
func handle(response []byte) string {
	if len(response) < 9 || response[0] != 102 {
		fail("SFTP expected handle: %q", response)
	}
	n := binary.BigEndian.Uint32(response[5:9])
	if n > uint32(len(response)-9) {
		fail("truncated SFTP handle")
	}
	return string(response[9 : 9+n])
}
func (p *sftpProbe) write(path string, contents []byte, mode uint32) {
	h := handle(p.request(3, str(path), u32(2|8|16), u32(4), u32(mode)))
	sftpStatus(p.request(6, str(h), make([]byte, 8), str(string(contents))), 0)
	// FSTAT exercises the real opened-handle adapter, not path STAT.
	response := p.request(8, str(h))
	if response[0] != 105 {
		fail("SFTP fstat failed: %q", response)
	}
	sftpStatus(p.request(4, str(h)), 0)
}
func (p *sftpProbe) directory(path, owner string) {
	h := handle(p.request(11, str(path)))
	response := p.request(12, str(h))
	if response[0] != 104 || !bytes.Contains(response, []byte(owner)) {
		fail("SFTP owner listing missing %q: %q", owner, response)
	}
	sftpStatus(p.request(4, str(h)), 0)
}
func (p *sftpProbe) renameFailure(old, target string) {
	response := p.request(18, str(old), str(target))
	if len(response) < 9 || response[0] != 101 || binary.BigEndian.Uint32(response[5:9]) == 0 {
		fail("SFTP invalid rename unexpectedly succeeded: %q", response)
	}
}
func (p *sftpProbe) readDenied(path string) {
	sftpStatus(p.request(3, str(path), u32(1), u32(0)), 3)
	p.session.Close()
}
func (p *sftpProbe) writeDenied(path string) {
	sftpStatus(p.request(3, str(path), u32(2|8|16), u32(0)), 3)
}

func (p *sftpProbe) sharedInode(client *ssh.Client, run func(*ssh.Client, string, int) string) {
	offset := func(n uint64) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, n)
		return b
	}
	write := func(h string, at uint64, data string) {
		sftpStatus(p.request(6, str(h), offset(at), str(data)), 0)
	}
	read := func(h, expected string) {
		response := p.request(5, str(h), offset(0), u32(100))
		if len(response) < 9 || response[0] != 103 || string(response[9:]) != expected {
			fail("SFTP open-inode read expected %q: %q", expected, response)
		}
	}
	size := func(h string, expected uint64) {
		response := p.request(8, str(h))
		if len(response) < 17 || response[0] != 105 || binary.BigEndian.Uint32(response[5:9])&1 == 0 || binary.BigEndian.Uint64(response[9:17]) != expected {
			fail("SFTP inode size expected%d: %q", expected, response)
		}
	}
	h1 := handle(p.request(3, str("/tmp/inode-wire"), u32(2|8|16), u32(0)))
	write(h1, 0, "ABC")
	reader := handle(p.request(3, str("/tmp/inode-wire"), u32(1), u32(0)))
	h2 := handle(p.request(3, str("/tmp/inode-wire"), u32(2), u32(0)))
	write(h1, 3, "D")
	write(h2, 4, "E")
	read(reader, "ABCDE")
	size(h1, 5)
	size(h2, 5)
	sftpStatus(p.request(18, str("/tmp/inode-wire"), str("/tmp/inode-renamed")), 0)
	sftpStatus(p.request(4, str(h1)), 0)
	if got := run(client, "cat /tmp/inode-renamed", 0); got != "ABCDE" {
		fail("SFTP first close lost shared writes: %q", got)
	}
	sftpStatus(p.request(13, str("/tmp/inode-renamed")), 0)
	p.write("/tmp/inode-renamed", []byte("replacement"), 0600)
	write(h2, 5, "F")
	sftpStatus(p.request(4, str(h2)), 0)
	read(reader, "ABCDEF")
	size(reader, 6)
	sftpStatus(p.request(4, str(reader)), 0)
	if got := run(client, "cat /tmp/inode-renamed", 0); got != "replacement" {
		fail("SFTP old unlinked inode changed replacement: %q", got)
	}
	quota := handle(p.request(3, str("/tmp/inode-quota"), u32(2|8|16), u32(0)))
	sftpStatus(p.request(6, str(quota), offset(1<<30), str("x")), 4)
	size(quota, 0)
	sftpStatus(p.request(4, str(quota)), 0)
	copyTarget := handle(p.request(3, str("/tmp/copy-open-wire"), u32(2|8|16), u32(0)))
	write(copyTarget, 0, "old")
	p.write("/tmp/copy-source-wire", []byte("NEW"), 0600)
	run(client, "cp /tmp/copy-source-wire /tmp/copy-open-wire", 0)
	write(copyTarget, 3, "!")
	if got := run(client, "cat /tmp/copy-open-wire", 0); got != "NEW!" {
		fail("cp detached an open SFTP descriptor: %q", got)
	}
	sftpStatus(p.request(4, str(copyTarget)), 0)
	if got := run(client, "cat /tmp/copy-open-wire; cat /tmp/copy-source-wire", 0); got != "NEW!NEW" {
		fail("cp/SFTP close altered destination or immutable source: %q", got)
	}
	cross := handle(p.request(3, str("/tmp/cross-wire"), u32(2|8|16), u32(0)))
	write(cross, 0, "ABC")
	run(client, "printf D >> /tmp/cross-wire", 0)
	write(cross, 4, "E")
	sftpStatus(p.request(4, str(cross)), 0)
	if got := run(client, "cat /tmp/cross-wire", 0); got != "ABCDE" {
		fail("SSH redirection/SFTP overlap lost content: %q", got)
	}
}
