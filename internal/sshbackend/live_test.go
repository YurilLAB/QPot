//go:build linux

package sshbackend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSSHBackendLive follows genuine OpenSSH exec/SFTP requests in an entirely
// network-none container. The Docker exec bridge carries bytes, not SSH parsing.
// A separate organization test must establish broker/cell routing containment.
func TestSSHBackendLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_SSH_BACKEND") != "1" {
		t.Skip("set QPOT_TEST_SSH_BACKEND=1 for real backend integration")
	}
	image := os.Getenv("QPOT_SSH_BACKEND_IMAGE")
	if image == "" {
		image = "qpot-local/ssh-backend:development"
	}
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	logs := filepath.Join(root, "logs")
	audit := filepath.Join(root, "context")
	for _, dir := range []string{keys, logs, audit} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"ed25519", "rsa", "ecdsa"} {
		cmd := exec.Command("ssh-keygen", "-q", "-t", kind, "-N", "", "-f", filepath.Join(keys, "ssh_host_"+kind+"_key"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("test hostkeys: %v %s", err, output)
		}
		// Read-only Desktop mounts can report0777. sshd must use private
		// runtime copies without chmodding or regenerating these source keys.
		if err := os.Chmod(filepath.Join(keys, "ssh_host_"+kind+"_key"), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(keys, 0o777); err != nil {
		t.Fatal(err)
	}
	hostBytes, err := os.ReadFile(filepath.Join(keys, "ssh_host_ed25519_key"))
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.ParsePrivateKey(hostBytes)
	if err != nil {
		t.Fatal(err)
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
	generation := uint64(0)
	connection := ConnectionContext{SessionID: strings.Repeat("a", 32), SrcIP: "198.51.100.42", SrcPort: 44001, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Generation: &generation}
	contextBytes, _ := json.Marshal(connection)
	contextFile := filepath.Join(audit, "connection.json")
	if err := os.WriteFile(contextFile, contextBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(contextFile, 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("qpot-ssh-backend-live-%d", time.Now().UnixNano())
	mappedOwner := backendMappedOwner(t, image)
	args := []string{"run", "-d", "--name", name, "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "0.5", "--pids-limit", "128", "--label", "qpot.validation=ssh-backend-live", "--mount", "type=bind,src=" + keys + ",dst=" + HostKeySourceDirectory + ",readonly", "--mount", "type=bind,src=" + logs + ",dst=/var/log/ssh-backend", "--mount", "type=bind,src=" + audit + ",dst=/run/audit-context,readonly", "--env", "BACKEND_USERS=root:labroot123,operator:laboperator123", "--env", "BACKEND_SCENE=" + string(scene)}
	for _, capability := range []string{"SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETPCAP", "KILL", "SYS_CHROOT", "AUDIT_WRITE", "NET_BIND_SERVICE"} {
		args = append(args, "--cap-add", capability)
	}
	args = append(args, image)
	if output, err := backendDocker(time.Minute, args...); err != nil {
		t.Fatalf("start backend: %v %s", err, output)
	}
	t.Cleanup(func() {
		_, _ = backendDocker(15*time.Second, "stop", "--time", "5", name)
		output, _ := backendDocker(10*time.Second, "logs", name)
		if t.Failed() {
			t.Logf("backend log: %s", output)
		}
		_, _ = backendDocker(15*time.Second, "rm", "--volumes", name)
		// These are this test's private mapped-UID files, not production logs.
		// Restore ownership without widening0600/0700 modes for TempDir removal.
		cleanup := []string{"run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--user", "0:0", "--label", "qpot.validation=ssh-backend-live-cleanup", "--mount", "type=bind,src=" + logs + ",dst=/target", "--entrypoint", "/usr/bin/chown", image, "-R", "--no-dereference", mappedOwner, "/target"}
		if output, err := backendDocker(30*time.Second, cleanup...); err != nil {
			t.Errorf("clean owned mappedUID logs: %v %s", err, output)
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if _, err := backendDocker(3*time.Second, "exec", name, "/usr/local/libexec/session-audit", "health"); err == nil {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatal("backend did not become healthy")
	}
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
	run(`printf 'after\n' >> /srv/app/state; useradd -m analyst; test "$(getent passwd analyst | cut -d: -f7)" = /usr/local/bin/rec-shell`, 0)
	if output := run(`cat /srv/app/state; id analyst; test -d /home/analyst`, 0); !strings.HasPrefix(string(output), "before\nafter\nuid=") {
		t.Fatalf("file/user consequence: %q", output)
	}
	run(`! dpkg-query -W -f='${Status}' tree 2>/dev/null | grep -qx 'install ok installed'`, 0)
	run(`DEBIAN_FRONTEND=noninteractive apt-get --no-download -y install tree`, 0)
	if output := run(`dpkg-query -W -f='${Status}\n' tree; command -v tree; tree --version`, 0); !strings.Contains(string(output), "install ok installed") || !strings.Contains(string(output), "/usr/bin/tree") {
		t.Fatalf("real offline package install: %q", output)
	}
	run(`test -f /etc/debian_version; pg_dump --version | grep -q ' 15\.'`, 0)
	run(`set -eu; test "$(stat -c '%a %u' /run/sshd)" = '755 0'; test "$(stat -c '%a %u' /run/sshd/bootstrap)" = '700 0'; test "$(stat -c '%a %u' /run/sshd/hostkeys)" = '700 0'; for kind in rsa ecdsa ed25519; do source=/run/sshd/bootstrap/keys/ssh_host_${kind}_key; test "$(stat -c %a "$source")" = 777; test ! -w "$source"; test "$(stat -c '%a %u' /run/sshd/hostkeys/ssh_host_${kind}_key)" = '600 0'; cmp -s "$source" /run/sshd/hostkeys/ssh_host_${kind}_key; done; findmnt -n -o OPTIONS -T /run/sshd/bootstrap/keys | tr , '\n' | grep -qx ro`, 0)
	run(`if grep -zqE '^(BACKEND_SCENE|BACKEND_USERS|SESSION_CONTAINER|HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy)=' /proc/1/environ; then exit 9; fi`, 0)
	run(`if LC_ALL=C grep -aiqE 'qpot|honeypot|github.com/qpot' /usr/local/bin/entrypoint /usr/local/bin/rec-shell /etc/ssh/sshd_config /usr/local/libexec/session-audit; then exit 9; fi`, 0)
	operator := backendSSH(t, name, "operator", clientSigner, hostSigner.PublicKey())
	defer operator.Close()
	for _, mode := range []os.FileMode{0o600, 0o777} {
		for _, kind := range []string{"ed25519", "rsa", "ecdsa"} {
			if err := os.Chmod(filepath.Join(keys, "ssh_host_"+kind+"_key"), mode); err != nil {
				t.Fatal(err)
			}
		}
		denial := `set -eu; test ! -x /run/sshd/bootstrap; test ! -x /run/sshd/hostkeys; for kind in rsa ecdsa ed25519; do test ! -r /run/sshd/bootstrap/keys/ssh_host_${kind}_key; test ! -r /run/sshd/hostkeys/ssh_host_${kind}_key; done`
		session, err := operator.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		output, err := session.CombinedOutput(denial)
		session.Close()
		if err != nil || len(output) != 0 {
			t.Fatalf("ordinary SSH account can access source/private host keys with source mode %o: %s %v", mode, output, err)
		}
		if output, err := backendDocker(10*time.Second, "exec", "--user", "65534:65534", name, "/bin/sh", "-ec", denial); err != nil {
			t.Fatalf("unrelated UID can access source/private host keys with source mode %o: %s %v", mode, output, err)
		}
	}
	session, err := operator.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var operatorOut, operatorErr bytes.Buffer
	session.Stdout = &operatorOut
	session.Stderr = &operatorErr
	err = session.Run(`printf 'operator-output\n'; printf 'operator-error\n' >&2`)
	session.Close()
	if err != nil || operatorOut.String() != "operator-output\n" || operatorErr.String() != "operator-error\n" {
		t.Fatalf("non-root recording/login: out=%q err=%q failure=%v", operatorOut.String(), operatorErr.String(), err)
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
		t.Fatalf("startup must run inside the recorded command: stdout=%q stderr=%q %v", startupOutput.String(), startupError.String(), err)
	}
	run("rm /home/operator/.bashrc", 0)
	// no-new-privileges must also prevent the ordinary account using chsh's
	// setuid bit to replace the recording login shell with an unrecorded shell.
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
	if err := changeShell.Start("test -t 0 || exit 90; chsh -s /bin/bash"); err != nil {
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
	run(`test "$(getent passwd operator | cut -d: -f7)" = /usr/local/bin/rec-shell`, 0)
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
	// Accounts created during this visitor's session must also be able to log
	// in and create their own private recordings without bootstrap assistance.
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
		t.Fatalf("new account state/permissions/capture: %q %v", analystOutput, err)
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
	if data, err := backendDocker(10*time.Second, "exec", name, "/bin/sh", "-c", `test "$(stat -c %a /var/log/ssh-backend/sshd.log)" = 600 && grep -q 'Accepted publickey for operator' /var/log/ssh-backend/sshd.log`); err != nil {
		t.Fatalf("private real sshd authentication metadata: %v %s", err, data)
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
	// Read private records through the container's root, never broaden modes.
	records, err := backendDocker(10*time.Second, "exec", name, "/bin/sh", "-c", `cat /var/log/ssh-backend/uid-*/*.json`)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(records))
	seenOperator := false
	seenStartup, seenRestricted, seenBinary, seenSFTP, seenPostChange := false, false, false, false, false
	count := 0
	for {
		var event SessionEvent
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		count++
		if event.SessionID != connection.SessionID || event.SrcIP != connection.SrcIP || event.Attribution != "broker-cell" || event.PeerIP != "127.0.0.1" {
			t.Fatalf("source context/actual peer: %+v", event)
		}
		if event.Username == "operator" && strings.Contains(event.Stdout, "operator-output") && strings.Contains(event.Stderr, "operator-error") {
			seenOperator = true
		}
		if event.Phase != "finish" {
			continue
		}
		if event.Input == "printf startup-command" && event.Stderr == "startup-recorded" && event.Stdout == "startup-command" {
			seenStartup = true
		}
		if event.Input == "printf restricted-key" && event.Stdout == "restricted-key" {
			seenRestricted = true
		}
		if event.Input == "printf post-chsh-recorded" && event.Stdout == "post-chsh-recorded" {
			seenPostChange = true
		}
		var wantInput []byte
		if event.Input == "cat # binary-stdin-capture" {
			seenBinary, wantInput = true, binaryInput
		} else if event.Input == "/usr/lib/openssh/sftp-server" {
			seenSFTP, wantInput = true, sftpInput.Bytes()
		}
		if wantInput != nil {
			if !event.StdinRecorded || event.InputFile == "" || filepath.Base(event.InputFile) != event.InputFile || event.Truncated || event.CaptureError != "" {
				t.Fatalf("incomplete input archive: %+v", event)
			}
			inputPath := fmt.Sprintf("%s/uid-%d/%s", LogDirectory, event.UID, event.InputFile)
			data, err := backendDocker(10*time.Second, "exec", name, "/bin/cat", inputPath)
			if err != nil || !bytes.Equal(data, wantInput) {
				t.Fatalf("archived stdin differs for %q: got %d want %d err %v", event.Input, len(data), len(wantInput), err)
			}
		}
	}
	if count < 10 || !seenOperator || !seenStartup || !seenRestricted || !seenBinary || !seenSFTP || !seenPostChange {
		t.Fatalf("private JSONL capture: count=%d nonroot=%v startup=%v restricted=%v binary=%v sftp=%v post-chsh=%v", count, seenOperator, seenStartup, seenRestricted, seenBinary, seenSFTP, seenPostChange)
	}
	// A real container teardown must retain the START record, without adding a
	// fabricated finish/success after the recording process has been killed.
	abrupt, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := abrupt.Start("sleep 30"); err != nil {
		t.Fatal(err)
	}
	var abruptPath string
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		data, readErr := backendDocker(3*time.Second, "exec", name, "/bin/sh", "-c", `cat /var/log/ssh-backend/uid-0/*.json`)
		if readErr == nil {
			dec := json.NewDecoder(bytes.NewReader(data))
			for {
				var event SessionEvent
				if dec.Decode(&event) != nil {
					break
				}
				if event.Input == "sleep 30" && event.Phase == "start" {
					base := strings.TrimSuffix(event.StdoutFile, ".out") + ".json"
					if filepath.Base(base) != base {
						t.Fatal("invalid record path")
					}
					abruptPath = "/target/uid-0/" + base
					break
				}
			}
		}
		if abruptPath != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if abruptPath == "" {
		t.Fatal("long command did not persist its START record")
	}
	if output, err := backendDocker(10*time.Second, "kill", "--signal", "KILL", name); err != nil {
		t.Fatalf("owned abrupt teardown: %v %s", err, output)
	}
	_ = abrupt.Wait()
	_ = abrupt.Close()
	data, err := backendDocker(10*time.Second, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "0:0", "--entrypoint", "/bin/cat", "--mount", "type=bind,src="+logs+",dst=/target,readonly", image, abruptPath)
	if err != nil {
		t.Fatal(err)
	}
	var start SessionEvent
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&start); err != nil || start.Phase != "start" || start.ExitCode != nil {
		t.Fatalf("invalid aborted start: %s", data)
	}
	var fabricated SessionEvent
	if err := dec.Decode(&fabricated); err != io.EOF {
		t.Fatalf("abrupt teardown fabricated finish: %s", data)
	}
	t.Logf("real SSH state, users, offline package, non-root capture, SFTP and trusted context passed; %d command records", count)
}

func backendUint32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

func backendString(value []byte) []byte {
	return append(backendUint32(uint32(len(value))), value...)
}

func backendMappedOwner(t *testing.T, image string) string {
	t.Helper()
	var ids []string
	for _, item := range []struct {
		name string
		host int
	}{{"uid", os.Getuid()}, {"gid", os.Getgid()}} {
		data, err := backendDocker(20*time.Second, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "/bin/cat", image, "/proc/self/"+item.name+"_map")
		if err != nil {
			t.Fatalf("read%smap: %v %s", item.name, err, data)
		}
		mapped := ""
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			inside, a := strconv.ParseUint(fields[0], 10, 64)
			outside, b := strconv.ParseUint(fields[1], 10, 64)
			count, c := strconv.ParseUint(fields[2], 10, 64)
			if a == nil && b == nil && c == nil && item.host >= 0 && uint64(item.host) >= outside && uint64(item.host)-outside < count {
				mapped = strconv.FormatUint(inside+uint64(item.host)-outside, 10)
				break
			}
		}
		if mapped == "" {
			t.Fatalf("task%s%d is not mapped by Docker; cannot privately clean fixture", item.name, item.host)
		}
		ids = append(ids, mapped)
	}
	return strings.Join(ids, ":")
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
