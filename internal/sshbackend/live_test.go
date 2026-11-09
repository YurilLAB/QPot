//go:build linux

package sshbackend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/sshcapture"
	"golang.org/x/crypto/ssh"
)

// TestSSHBackendLive follows genuine OpenSSH exec/SFTP requests in an entirely
// network-none container. The Docker exec bridge carries bytes, not SSH parsing.
// The evidence comes from sshd's own capture, converted from the container's
// output by the same code the control plane runs. A separate organization test
// must establish broker/cell routing containment and attribution.
func TestSSHBackendLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_SSH_BACKEND") != "1" {
		t.Skip("set QPOT_TEST_SSH_BACKEND=1 for real backend integration")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	// Marshal once to assert this is a genuine OpenSSH key, not a fake token.
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil || len(pem.EncodeToMemory(block)) == 0 {
		t.Fatalf("client key: %v", err)
	}
	public := string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey()))
	_, restrictedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restrictedSigner, err := ssh.NewSignerFromKey(restrictedPrivate)
	if err != nil {
		t.Fatal(err)
	}
	operatorKeys := public + `command="printf restricted-key",no-pty ` + string(ssh.MarshalAuthorizedKey(restrictedSigner.PublicKey()))
	m := Manifest{Version: 1, Role: "app", Organization: "Workshop services", Directories: []Directory{{Path: "/root/.ssh", Mode: 0o700, Owner: "root"}, {Path: "/home/operator/.ssh", Mode: 0o700, Owner: "operator"}, {Path: "/srv/app", Mode: 0o755, Owner: "root"}}, Files: []File{{Path: "/root/.ssh/authorized_keys", Content: public, Mode: 0o600, Owner: "root"}, {Path: "/home/operator/.ssh/authorized_keys", Content: operatorKeys, Mode: 0o600, Owner: "operator"}}}
	scene, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	name, keys, hostSigner := liveBackend(t, "root:labroot123,operator:laboperator123", scene)
	client := backendSSH(t, name, "root", clientSigner, hostSigner.PublicKey())
	defer client.Close()
	for _, kind := range []struct {
		name, algorithm string
	}{
		{"rsa", ssh.KeyAlgoRSASHA512},
		{"ecdsa", ssh.KeyAlgoECDSA256},
	} {
		privateKey, err := os.ReadFile(filepath.Join(keys, "ssh_host_"+kind.name+"_key"))
		if err != nil {
			t.Fatal(err)
		}
		expected, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peer := backendSSHWithAlgorithms(t, name, "root", clientSigner, expected.PublicKey(), []string{kind.algorithm})
		_ = peer.Close()
	}
	run := func(command string, want int) []byte {
		t.Helper()
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		output, err := session.CombinedOutput(command)
		code := 0
		if err != nil {
			exit, ok := err.(*ssh.ExitError)
			if !ok {
				t.Fatalf("exec %q: %v", command, err)
			}
			code = exit.ExitStatus()
		}
		if code != want {
			t.Fatalf("exec %q exit %d want %d: %s", command, code, want, output)
		}
		return output
	}
	run(`printf 'before\n' > /srv/app/state; chmod 640 /srv/app/state`, 0)
	if output := run(`cat /srv/app/state; stat -c '%a' /srv/app/state`, 0); string(output) != "before\n640\n" {
		t.Fatalf("state did not persist across exec channels: %q", output)
	}
	// A new account gets Debian's own useradd default, as on any Debian host.
	run(`printf 'after\n' >> /srv/app/state; useradd -m analyst; test "$(getent passwd analyst | cut -d: -f7)" = /bin/sh`, 0)
	if output := run(`cat /srv/app/state; id analyst; test -d /home/analyst`, 0); !strings.HasPrefix(string(output), "before\nafter\nuid=") {
		t.Fatalf("file/user consequence: %q", output)
	}
	run(`! dpkg-query -W -f='${Status}' tree 2>/dev/null | grep -qx 'install ok installed'`, 0)
	run(`DEBIAN_FRONTEND=noninteractive apt-get --no-download -y install tree`, 0)
	if output := run(`dpkg-query -W -f='${Status}\n' tree; command -v tree; tree --version`, 0); !strings.Contains(string(output), "install ok installed") || !strings.Contains(string(output), "/usr/bin/tree") {
		t.Fatalf("real offline package install: %q", output)
	}
	run(`test -f /etc/debian_version; pg_dump --version | grep -q ' 15\.'`, 0)
	// Nothing in the guest is the recorder's: the process list, accounts,
	// files, packages, mounts and sshd's own environment look stock.
	run(`set -eu
trap 'echo "failed at line $LINENO" >&2' ERR
test "$(ps -o args= -p 1 | cut -d'[' -f1)" = 'sshd: /usr/sbin/sshd -D -e '
if ps -eo comm= | grep -iqE 'session-audit|rec-shell|qpot|honeypot|record'; then exit 10; fi
for account in root operator; do test "$(getent passwd $account | cut -d: -f7)" = /bin/bash; done
if grep -qvE '^(#.*|/bin/sh|/usr/bin/sh|/bin/bash|/usr/bin/bash|/bin/rbash|/usr/bin/rbash|/bin/dash|/usr/bin/dash)$' /etc/shells; then exit 11; fi
for gone in /run/audit-context /var/log/ssh-backend /usr/local/libexec /run/sshd/hostkeys /run/sshd/bootstrap /usr/local/bin/rec-shell /usr/local/bin/entrypoint; do test ! -e $gone; done
for dir in /usr/local/bin /usr/local/sbin; do test -z "$(ls -A $dir)"; done
test "$(stat -c '%a %u' /run/sshd)" = '755 0'
test "$(stat -c '%a %u' /etc/ssh)" = '755 0'
for kind in rsa ecdsa ed25519; do
  test "$(stat -c '%a %u' /etc/ssh/ssh_host_${kind}_key)" = '600 0'
  test "$(stat -c '%a %u' /etc/ssh/ssh_host_${kind}_key.pub)" = '644 0'
  ssh-keygen -y -f /etc/ssh/ssh_host_${kind}_key | cut -d' ' -f1-2 | cmp -s - <(cut -d' ' -f1-2 /etc/ssh/ssh_host_${kind}_key.pub)
done
test -z "$(dpkg -V openssh-server openssh-client openssh-sftp-server | grep -v '^missing ')"
test "$(ls /proc/1/fd | sort -n | xargs)" = "0 1 2 3"
if grep -iqE 'qpot|honeypot|session-store|records|identities|audit|hostkeys' /proc/self/mountinfo; then exit 12; fi
if LC_ALL=C grep -aiqE 'qpot|honeypot|qpcapture|session-audit' /usr/sbin/sshd /etc/ssh/sshd_config /etc/passwd /etc/shells /etc/default/useradd; then exit 13; fi
if grep -zqE '^(BACKEND_[A-Z_]*|SESSION_CONTAINER|HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy)=' /proc/1/environ; then exit 14; fi
`, 0)
	// A command inherits only its own three streams from sshd: no capture
	// or log descriptor. exec leaves no shell that could open pipes itself.
	links, streams := 0, 0
	for _, line := range strings.Split(string(run(`exec ls -l /proc/self/fd`, 0)), "\n") {
		if _, target, ok := strings.Cut(line, " -> "); ok {
			links++
			if strings.HasPrefix(target, "pipe:") || strings.HasPrefix(target, "socket:") {
				streams++
			}
		}
	}
	if links != 4 || streams != 3 {
		t.Fatalf("a session command inherited more than its streams: %d descriptors, %d pipes or sockets", links, streams)
	}
	operator := backendSSH(t, name, "operator", clientSigner, hostSigner.PublicKey())
	defer operator.Close()
	denial := `set -eu; for kind in rsa ecdsa ed25519; do test ! -r /etc/ssh/ssh_host_${kind}_key; done; if ls /proc/$PPID/fd >/dev/null 2>&1; then exit 3; fi`
	session, err := operator.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := session.CombinedOutput(denial); err != nil || len(output) != 0 {
		t.Fatalf("ordinary SSH account can read private host keys or its sshd's descriptors: %s %v", output, err)
	}
	session.Close()
	if output, err := backendDocker(10*time.Second, "exec", "--user", "65534:65534", name, "/bin/sh", "-ec", `for kind in rsa ecdsa ed25519; do test ! -r /etc/ssh/ssh_host_${kind}_key; done`); err != nil {
		t.Fatalf("unrelated UID can read private host keys: %s %v", output, err)
	}
	session, err = operator.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var operatorOut, operatorErr bytes.Buffer
	session.Stdout = &operatorOut
	session.Stderr = &operatorErr
	err = session.Run(`printf 'operator-output\n'; printf 'operator-error\n' >&2`)
	session.Close()
	if err != nil || operatorOut.String() != "operator-output\n" || operatorErr.String() != "operator-error\n" {
		t.Fatalf("non-root login: out=%q err=%q failure=%v", operatorOut.String(), operatorErr.String(), err)
	}
	restricted := backendSSH(t, name, "operator", restrictedSigner, hostSigner.PublicKey())
	restrictedSession, err := restricted.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	restrictedOutput, err := restrictedSession.CombinedOutput("printf forbidden-key-command")
	restrictedSession.Close()
	restricted.Close()
	if err != nil || string(restrictedOutput) != "restricted-key" {
		t.Fatalf("authorized-key forced command was overridden: %q %v", restrictedOutput, err)
	}
	startup, err := operator.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := startup.CombinedOutput(`printf '%s\n' 'printf startup-recorded >&2' > /home/operator/.bashrc`); err != nil {
		t.Fatalf("ordinary user startup fixture: %s %v", output, err)
	}
	startup.Close()
	startup, err = operator.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var startupOutput, startupError bytes.Buffer
	startup.Stdout, startup.Stderr = &startupOutput, &startupError
	err = startup.Run("printf startup-command")
	startup.Close()
	if err != nil || startupOutput.String() != "startup-command" || startupError.String() != "startup-recorded" {
		t.Fatalf("startup output: stdout=%q stderr=%q %v", startupOutput.String(), startupError.String(), err)
	}
	run("rm /home/operator/.bashrc", 0)
	// no-new-privileges must keep chsh's setuid bit from working: an
	// ordinary account cannot rewrite the account database.
	changeShell, err := operator.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := changeShell.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	changeInput, err := changeShell.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var changeOutput, changeError bytes.Buffer
	changeShell.Stdout, changeShell.Stderr = &changeOutput, &changeError
	if err := changeShell.Start("test -t 0 || exit 90; chsh -s /bin/sh"); err != nil {
		t.Fatal(err)
	}
	var changeStatus []byte
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		data, err := backendDocker(3*time.Second, "exec", name, "/bin/sh", "-c", `pid=$(pgrep -u operator -x chsh | head -n 1); test -n "$pid" && grep -E '^(Uid|NoNewPrivs):' /proc/$pid/status`)
		if err == nil {
			changeStatus = data
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !bytes.Contains(changeStatus, []byte("Uid:\t1000\t1000\t1000\t1000")) || !bytes.Contains(changeStatus, []byte("NoNewPrivs:\t1")) {
		t.Fatalf("setuid chsh did not remain an ordinary process under no-new-privileges: %q", changeStatus)
	}
	t.Logf("actual PTY chsh status: %s", changeStatus)
	if _, err := io.WriteString(changeInput, "laboperator123\n"); err != nil {
		t.Fatal(err)
	}
	changeInput.Close()
	changeDone := make(chan error, 1)
	go func() { changeDone <- changeShell.Wait() }()
	select {
	case err := <-changeDone:
		if exit, ok := err.(*ssh.ExitError); !ok || exit.ExitStatus() == 0 || exit.ExitStatus() == 90 {
			t.Fatalf("ordinary PTY chsh unexpectedly succeeded or lacked a TTY: %q %v", changeOutput.String(), err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary PTY chsh did not finish")
	}
	changeShell.Close()
	run(`test "$(getent passwd operator | cut -d: -f7)" = /bin/bash`, 0)
	postChange, err := operator.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := postChange.CombinedOutput("printf post-chsh-recorded"); err != nil || string(output) != "post-chsh-recorded" {
		t.Fatalf("ordinary exec after chsh: %q %v", output, err)
	}
	postChange.Close()
	// Completing an exec must not require EOF from the SSH client.
	openInput, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	openStdin, err := openInput.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var earlyOutput bytes.Buffer
	openInput.Stdout = &earlyOutput
	if err := openInput.Start("printf open-input-complete"); err != nil {
		t.Fatal(err)
	}
	earlyDone := make(chan error, 1)
	go func() { earlyDone <- openInput.Wait() }()
	select {
	case err := <-earlyDone:
		if err != nil || earlyOutput.String() != "open-input-complete" {
			t.Fatalf("open input result %q %v", earlyOutput.String(), err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("completed SSH exec waited for client stdin EOF")
	}
	openStdin.Close()
	openInput.Close()
	binaryInput := bytes.Repeat([]byte{0, 255, 13, 10, 'a'}, 8192)
	binarySession, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	binarySession.Stdin = bytes.NewReader(binaryInput)
	binaryOutput, err := binarySession.Output("cat # binary-stdin-capture")
	binarySession.Close()
	if err != nil || !bytes.Equal(binaryOutput, binaryInput) {
		t.Fatalf("binary stdin delivery changed: %d %v", len(binaryOutput), err)
	}
	// Accounts created during this visitor's session are recorded too: sshd
	// records every account, whatever its shell.
	run(`install -d -o analyst -g analyst -m 700 /home/analyst/.ssh; install -o analyst -g analyst -m 600 /root/.ssh/authorized_keys /home/analyst/.ssh/authorized_keys; printf 'analyst:lab-analyst-pass\n' | chpasswd`, 0)
	analyst := backendSSH(t, name, "analyst", clientSigner, hostSigner.PublicKey())
	analystSession, err := analyst.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	analystOutput, err := analystSession.CombinedOutput(`printf 'new-account-output\n'; test ! -r /srv/app/state`)
	analystSession.Close()
	analyst.Close()
	if err != nil || string(analystOutput) != "new-account-output\n" {
		t.Fatalf("new account state/permissions: %q %v", analystOutput, err)
	}
	pty, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := pty.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	pty.Stdin = strings.NewReader("sample-input\n")
	ptyOutput, err := pty.CombinedOutput(`read -r reply; printf 'pty:%s\n' "$reply"; exit 3`)
	pty.Close()
	if exit, ok := err.(*ssh.ExitError); !ok || exit.ExitStatus() != 3 || !strings.Contains(string(ptyOutput), "pty:sample-input") {
		t.Fatalf("real SSH PTY: %q %v", ptyOutput, err)
	}
	// A binary SFTP response must have no wrapper text preceding its framing.
	sftp, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sftp.Close()
	in, err := sftp.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sftp.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sftp.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	var sftpInput bytes.Buffer
	writePacket := func(packet []byte) {
		t.Helper()
		frame := append(backendUint32(uint32(len(packet))), packet...)
		sftpInput.Write(frame)
		if _, err := in.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	readPacket := func() []byte {
		t.Helper()
		var size [4]byte
		if _, err := io.ReadFull(out, size[:]); err != nil {
			t.Fatal(err)
		}
		n := binary.BigEndian.Uint32(size[:])
		if n < 5 || n > 65536 {
			t.Fatalf("invalid SFTP framing length %d", n)
		}
		packet := make([]byte, n)
		if _, err := io.ReadFull(out, packet); err != nil {
			t.Fatal(err)
		}
		return packet
	}
	writePacket([]byte{1, 0, 0, 0, 3})
	var size [4]byte
	if _, err := io.ReadFull(out, size[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < 5 || n > 65536 {
		t.Fatalf("invalid SFTP framing length %d", n)
	}
	packet := make([]byte, n)
	if _, err := io.ReadFull(out, packet); err != nil {
		t.Fatal(err)
	}
	if packet[0] != 2 || binary.BigEndian.Uint32(packet[1:5]) != 3 {
		t.Fatalf("SFTP reply %v", packet[:5])
	}
	openPacket := append([]byte{3}, backendUint32(1)...)
	openPacket = append(openPacket, backendString([]byte("/srv/app/sftp-upload"))...)
	openPacket = append(openPacket, backendUint32(26)...)
	openPacket = append(openPacket, backendUint32(0)...)
	writePacket(openPacket)
	handlePacket := readPacket()
	if handlePacket[0] != 102 || len(handlePacket) < 9 || int(binary.BigEndian.Uint32(handlePacket[5:9])) != len(handlePacket)-9 {
		t.Fatalf("SFTP handle: %v", handlePacket)
	}
	handle := handlePacket[5:]
	sftpPayload := []byte{'S', 'F', 'T', 'P', 0, 255, 13, 10}
	write := append([]byte{6}, backendUint32(2)...)
	write = append(write, handle...)
	write = append(write, make([]byte, 8)...)
	write = append(write, backendString(sftpPayload)...)
	writePacket(write)
	if status := readPacket(); status[0] != 101 || len(status) < 9 || binary.BigEndian.Uint32(status[5:9]) != 0 {
		t.Fatalf("SFTP write status %v", status)
	}
	closePacket := append([]byte{4}, backendUint32(3)...)
	closePacket = append(closePacket, handle...)
	writePacket(closePacket)
	if status := readPacket(); status[0] != 101 || len(status) < 9 || binary.BigEndian.Uint32(status[5:9]) != 0 {
		t.Fatalf("SFTP close status %v", status)
	}
	_ = in.Close()
	// RequestSubsystem does not call Session.Start in x/crypto/ssh, so Wait
	// would fail locally with "session not started" despite a real response.
	if extra, err := io.ReadAll(out); err != nil || len(extra) != 0 {
		t.Fatalf("SFTP EOF framing: %q %v", extra, err)
	}
	_ = sftp.Close()
	if data := run("cat /srv/app/sftp-upload", 0); !bytes.Equal(data, sftpPayload) {
		t.Fatalf("SFTP file bytes changed: %q", data)
	}
	// The capture so far, converted as the control plane does it. Replaying
	// the same container output again later must rewrite the same files.
	evidence := t.TempDir()
	converter := sshcapture.DockerConverter(func(context.Context) (func(), error) { return func() {}, nil })
	target := sshcapture.Target{Service: "ssh-backend-live", Container: name, Dir: func() (string, error) { return evidence, nil }}
	drain := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := converter.Drain(ctx, target); err != nil {
			t.Fatalf("convert the capture: %v", err)
		}
	}
	drain()
	if data, err := os.ReadFile(filepath.Join(evidence, sshcapture.AuthLog)); err != nil || !bytes.Contains(data, []byte("Accepted publickey for operator")) {
		t.Fatalf("sshd's authentication log: %v %q", err, data)
	}
	finished := map[string]sshcapture.SessionEvent{}
	starts := 0
	readEvidence := func(file string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(evidence, file))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	records, err := filepath.Glob(filepath.Join(evidence, "uid-*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		data, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(record)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("record %s is not private: %v %v", record, info, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var event sshcapture.SessionEvent
			if err := decoder.Decode(&event); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if event.PeerIP != "127.0.0.1" || event.Attribution != "peer-only" || event.Username == "" ||
				filepath.Base(filepath.Dir(record)) != fmt.Sprintf("uid-%d", event.UID) {
				t.Fatalf("record origin: %+v", event)
			}
			if event.Phase == "start" {
				starts++
				continue
			}
			finished[event.Input] = event
		}
	}
	want := func(input, user string, code int, stdout, stderr string) sshcapture.SessionEvent {
		t.Helper()
		event, ok := finished[input]
		if !ok || event.Username != user || event.ExitCode == nil || *event.ExitCode != code ||
			event.Stdout != stdout || event.Stderr != stderr || event.Truncated || event.CaptureError != "" {
			t.Fatalf("record of %q: %+v (found %v)", input, event, ok)
		}
		if got := readEvidence(filepath.Join(fmt.Sprintf("uid-%d", event.UID), event.StdoutFile)); string(got) != stdout {
			t.Fatalf("%q output file %q", input, got)
		}
		return event
	}
	want(`printf 'operator-output\n'; printf 'operator-error\n' >&2`, "operator", 0, "operator-output\n", "operator-error\n")
	want("printf startup-command", "operator", 0, "startup-command", "startup-recorded")
	want("printf restricted-key", "operator", 0, "restricted-key", "")
	want("printf post-chsh-recorded", "operator", 0, "post-chsh-recorded", "")
	want(`printf 'new-account-output\n'; test ! -r /srv/app/state`, "analyst", 0, "new-account-output\n", "")
	ptyEvent, ok := finished[`read -r reply; printf 'pty:%s\n' "$reply"; exit 3`]
	if !ok || ptyEvent.Username != "root" || ptyEvent.ExitCode == nil || *ptyEvent.ExitCode != 3 || !strings.Contains(ptyEvent.Stdout, "pty:sample-input") ||
		!ptyEvent.PTY || ptyEvent.TimingFile == "" || len(readEvidence(filepath.Join("uid-0", ptyEvent.TimingFile))) == 0 ||
		string(readEvidence(filepath.Join("uid-0", ptyEvent.InputFile))) != "sample-input\n" {
		t.Fatalf("PTY session record: %+v", ptyEvent)
	}
	for input, wantInput := range map[string][]byte{"cat # binary-stdin-capture": binaryInput, "/usr/lib/openssh/sftp-server": sftpInput.Bytes()} {
		event, ok := finished[input]
		if !ok || !event.StdinRecorded || event.InputFile == "" || event.Truncated || event.CaptureError != "" {
			t.Fatalf("incomplete input archive for %q: %+v", input, event)
		}
		if data := readEvidence(filepath.Join(fmt.Sprintf("uid-%d", event.UID), event.InputFile)); !bytes.Equal(data, wantInput) {
			t.Fatalf("archived stdin differs for %q: got %d want %d", input, len(data), len(wantInput))
		}
	}
	if len(finished) < 10 || starts != len(records) {
		t.Fatalf("capture: %d finished commands, %d starts in %d records", len(finished), starts, len(records))
	}
	// A real container teardown keeps the start record, without a fabricated
	// finish: the converter only finishes what sshd saw end.
	abrupt, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := abrupt.Start("sleep 30"); err != nil {
		t.Fatal(err)
	}
	probe := t.TempDir()
	probeTarget := sshcapture.Target{Service: "ssh-backend-live", Container: name, Dir: func() (string, error) { return probe, nil }}
	opened := false
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until) && !opened; time.Sleep(50 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := converter.Drain(ctx, probeTarget)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob(filepath.Join(probe, "uid-0", "*.json"))
		for _, file := range files {
			if data, err := os.ReadFile(file); err == nil && bytes.Contains(data, []byte(`"input":"sleep 30"`)) {
				opened = true
			}
		}
	}
	if !opened {
		t.Fatal("the long command's open record never reached the container output")
	}
	if output, err := backendDocker(10*time.Second, "kill", "--signal", "KILL", name); err != nil {
		t.Fatalf("owned abrupt teardown: %v %s", err, output)
	}
	_ = abrupt.Wait()
	_ = abrupt.Close()
	drain()
	again, err := filepath.Glob(filepath.Join(evidence, "uid-*", "*.json"))
	if err != nil || len(again) != len(records)+1 {
		t.Fatalf("replay changed the records: %d then %d (%v)", len(records), len(again), err)
	}
	for _, record := range again {
		data, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte(`"input":"sleep 30"`)) {
			if lines := bytes.Count(data, []byte("\n")); lines != 2 {
				t.Fatalf("replay duplicated or lost a record line in %s: %d lines", record, lines)
			}
			continue
		}
		var start sshcapture.SessionEvent
		if err := json.Unmarshal(bytes.TrimSpace(data), &start); err != nil || start.Phase != "start" || start.ExitCode != nil {
			t.Fatalf("abrupt teardown fabricated a finish: %s", data)
		}
	}
	t.Logf("real SSH state, users, offline package, clean guest, sshd capture, SFTP and replay passed; %d command records", len(again))
}

// liveBackend starts the backend image, network-none and without mounts, with
// the given accounts and scene and fresh host keys (kept in keys), and waits
// for its banner. The container is removed when the test ends.
func liveBackend(t *testing.T, users string, scene []byte) (name, keys string, host ssh.Signer) {
	t.Helper()
	image := os.Getenv("QPOT_SSH_BACKEND_IMAGE")
	if image == "" {
		image = "qpot-local/ssh-backend:development"
	}
	keys = t.TempDir()
	var hostKeys []string
	for _, kind := range hostKeyKinds {
		file := filepath.Join(keys, "ssh_host_"+kind+"_key")
		if output, err := exec.Command("ssh-keygen", "-q", "-t", kind, "-N", "", "-f", file).CombinedOutput(); err != nil {
			t.Fatalf("test hostkeys: %v %s", err, output)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		hostKeys = append(hostKeys, kind+":"+base64.StdEncoding.EncodeToString(data))
	}
	hostBytes, err := os.ReadFile(filepath.Join(keys, "ssh_host_ed25519_key"))
	if err != nil {
		t.Fatal(err)
	}
	if host, err = ssh.ParsePrivateKey(hostBytes); err != nil {
		t.Fatal(err)
	}
	name = fmt.Sprintf("qpot-ssh-backend-live-%d", time.Now().UnixNano())
	// No mounts: the guest's mount table must name nothing on the host.
	args := []string{"run", "-d", "--name", name, "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "0.5", "--pids-limit", "128", "--label", "qpot.validation=ssh-backend-live", "--env", "BACKEND_USERS=" + users, "--env", "BACKEND_SCENE=" + string(scene), "--env", HostKeysVariable + "=" + strings.Join(hostKeys, ",")}
	for _, capability := range []string{"SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETPCAP", "KILL", "SYS_CHROOT", "AUDIT_WRITE", "NET_BIND_SERVICE"} {
		args = append(args, "--cap-add", capability)
	}
	args = append(args, image)
	if output, err := backendDocker(time.Minute, args...); err != nil {
		t.Fatalf("start backend: %v %s", err, output)
	}
	t.Cleanup(func() {
		_, _ = backendDocker(15*time.Second, "stop", "--time", "5", name)
		if t.Failed() {
			cmd := exec.Command("docker", "logs", "--tail", "200", name)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			_ = cmd.Run()
			t.Logf("sshd log: %s", stderr.String())
		}
		_, _ = backendDocker(15*time.Second, "rm", "--volumes", name)
	})
	// Readiness from outside the guest's process list: only the banner.
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		banner, err := backendDocker(3*time.Second, "exec", name, "/bin/bash", "-c", `exec 3<>/dev/tcp/127.0.0.1/22 && head -c 8 <&3`)
		if err == nil && string(banner) == "SSH-2.0-" {
			return name, keys, host
		}
	}
	t.Fatal("backend did not serve an SSH banner")
	return "", "", nil
}

// TestSSHBackendCaptureCostLive floods one connection with single bytes,
// echoed one at a time, and bulk output over more channels than its budget
// holds. sshd
// charges each record what it costs in the container log, so the log grows
// by at most 64 MiB for the connection, Docker's framing included; each
// channel's record says it was cut short, a channel past the budget is not
// recorded at all, and the session itself still carries every byte.
func TestSSHBackendCaptureCostLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_SSH_BACKEND") != "1" {
		t.Skip("set QPOT_TEST_SSH_BACKEND=1 for real backend integration")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Version: 1, Role: "app", Organization: "Workshop services", Directories: []Directory{{Path: "/root/.ssh", Mode: 0o700, Owner: "root"}}, Files: []File{{Path: "/root/.ssh/authorized_keys", Content: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), Mode: 0o600, Owner: "root"}}}
	scene, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	name, _, host := liveBackend(t, "root:labroot123", scene)
	client := backendSSH(t, name, "root", signer, host.PublicKey())

	// Single bytes each way: the client waits for each echo, so sshd
	// records every byte on its own, about a hundred times its size.
	const rounds = 30000
	echo, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := echo.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := echo.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := echo.Start("cat # single bytes"); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	for i := 0; i < rounds; i++ {
		if _, err := stdin.Write([]byte{'x'}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(stdout, one); err != nil || one[0] != 'x' {
			t.Fatalf("the session lost byte %d: %q %v", i, one, err)
		}
	}
	_ = stdin.Close()
	if err := echo.Wait(); err != nil {
		t.Fatal(err)
	}
	_ = echo.Close()
	// Bulk out, on more channels than the connection's budget holds.
	const bulk, channels = 7_000_000, 9
	for i := 0; i < channels; i++ {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		var out countWriter
		session.Stdout = &out
		if err := session.Run(fmt.Sprintf("head -c %d /dev/zero # bulk %d", bulk, i)); err != nil || out.n != bulk {
			t.Fatalf("bulk %d reached the client with %d bytes: %v", i, out.n, err)
		}
		_ = session.Close()
	}
	_ = client.Close()
	if output, err := backendDocker(30*time.Second, "stop", "--time", "5", name); err != nil {
		t.Fatalf("stop backend: %v %s", err, output)
	}

	// What the connection added to the container log, as json-file writes
	// it: each line, its escaped newline, the stream and a timestamp.
	logs := exec.Command("docker", "logs", name)
	var stderr bytes.Buffer
	logs.Stderr = &stderr
	if err := logs.Run(); err != nil {
		t.Fatal(err)
	}
	const frame = len(`{"log":"\n","stream":"stderr","time":"2006-01-02T15:04:05.999999999Z"}` + "\n")
	var cost int
	for _, line := range bytes.SplitAfter(stderr.Bytes(), []byte("\n")) {
		if len(line) > 1 && line[len(line)-1] == '\n' {
			if _, err := sshcapture.ParseRecord(line[:len(line)-1]); err == nil {
				cost += len(line) - 1 + frame
			}
		}
	}
	if cost > 64<<20 || cost < 48<<20 {
		t.Fatalf("the connection added %d bytes of capture to the log, want up to 64 MiB and near it", cost)
	}

	evidence := t.TempDir()
	converter := sshcapture.DockerConverter(func(context.Context) (func(), error) { return func() {}, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := converter.Drain(ctx, sshcapture.Target{Service: "ssh-backend-live", Container: name, Dir: func() (string, error) { return evidence, nil }}); err != nil {
		t.Fatalf("convert the capture: %v", err)
	}
	records, err := filepath.Glob(filepath.Join(evidence, "uid-0", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	finished := map[string]sshcapture.SessionEvent{}
	for _, record := range records {
		data, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var event sshcapture.SessionEvent
			if err := decoder.Decode(&event); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if event.Phase != "start" {
				finished[event.Input] = event
			}
		}
	}
	kept := func(event sshcapture.SessionEvent, file string) int64 {
		t.Helper()
		info, err := os.Stat(filepath.Join(evidence, "uid-0", file))
		if err != nil {
			t.Fatalf("%q: %v", event.Input, err)
		}
		return info.Size()
	}
	single, ok := finished["cat # single bytes"]
	if !ok || !single.Truncated || !single.StdinRecorded {
		t.Fatalf("the single-byte channel's record (found %v): truncated %v, stdin %v %q, error %q", ok, single.Truncated, single.StdinRecorded, single.InputFile, single.CaptureError)
	}
	if n := kept(single, single.InputFile); n < rounds/2 || n >= rounds {
		t.Fatalf("kept %d of %d single bytes: the channel budget must count each record's cost", n, rounds)
	}
	recorded := 0
	for i := 0; i < channels; i++ {
		event, ok := finished[fmt.Sprintf("head -c %d /dev/zero # bulk %d", bulk, i)]
		if !ok {
			continue
		}
		recorded++
		if n := kept(event, event.StdoutFile); !event.Truncated || n >= bulk || n > 8<<20 {
			t.Fatalf("bulk %d kept %d bytes, truncated %v", i, n, event.Truncated)
		}
	}
	if recorded == 0 || recorded == channels {
		t.Fatalf("%d of %d bulk channels recorded: the connection's budget must end recording", recorded, channels)
	}
	t.Logf("capture cost %d bytes; %d of %d bulk channels recorded", cost, recorded, channels)
}

// countWriter counts what is written to it.
type countWriter struct{ n int }

func (w *countWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }

func backendUint32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

func backendString(value []byte) []byte {
	return append(backendUint32(uint32(len(value))), value...)
}

func backendDocker(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

type backendPipeConn struct {
	io.ReadCloser
	input  io.WriteCloser
	cmd    *exec.Cmd
	cancel context.CancelFunc
	once   sync.Once
}

func (c *backendPipeConn) Write(p []byte) (int, error) { return c.input.Write(p) }
func (c *backendPipeConn) Close() error {
	c.once.Do(func() { _ = c.input.Close(); _ = c.ReadCloser.Close(); c.cancel(); _ = c.cmd.Wait() })
	return nil
}
func (c *backendPipeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}
func (c *backendPipeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
}
func (c *backendPipeConn) SetDeadline(time.Time) error      { return nil }
func (c *backendPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *backendPipeConn) SetWriteDeadline(time.Time) error { return nil }

func backendSSH(t *testing.T, container, username string, signer ssh.Signer, hostkey ssh.PublicKey) *ssh.Client {
	t.Helper()
	return backendSSHWithAlgorithms(t, container, username, signer, hostkey, []string{ssh.KeyAlgoED25519})
}

func backendSSHWithAlgorithms(t *testing.T, container, username string, signer ssh.Signer, hostkey ssh.PublicKey, algorithms []string) *ssh.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container, "/bin/bash", "-c", `exec 3<>/dev/tcp/127.0.0.1/22; cat <&3 & cat >&3; exec 3>&-; wait`)
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	conn := &backendPipeConn{ReadCloser: out, input: in, cmd: cmd, cancel: cancel}
	t.Cleanup(func() { _ = conn.Close() })
	type result struct {
		client *ssh.Client
		err    error
	}
	done := make(chan result, 1)
	go func() {
		connection, channels, requests, err := ssh.NewClientConn(conn, "backend", &ssh.ClientConfig{User: username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyAlgorithms: algorithms, HostKeyCallback: ssh.FixedHostKey(hostkey)})
		if err != nil {
			done <- result{err: err}
			return
		}
		done <- result{client: ssh.NewClient(connection, channels, requests)}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			_ = conn.Close()
			t.Fatalf("real SSH handshake: %v (%s)", result.err, stderr.String())
		}
		return result.client
	case <-time.After(15 * time.Second):
		_ = conn.Close()
		t.Fatalf("real SSH handshake timed out (%s)", stderr.String())
		return nil
	}
}
