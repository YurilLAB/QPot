package sshbackend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// LogDirectory contains private session records read by the collector.
	LogDirectory = "/var/log/ssh-backend"
	// HostKeySourceDirectory is the read-only orchestration mount. Its private
	// parent protects source keys even when Desktop reports permissive modes.
	HostKeySourceDirectory = "/run/sshd/bootstrap/keys"
	defaultUsers           = "admin:admin,ubuntu:ubuntu,user:password,root:root123"
	loginShell             = "/usr/local/bin/rec-shell"
)

// Account is one bounded local account supplied by trusted orchestration.
type Account struct{ Name, Password string }

// ParseAccounts rejects malformed input instead of partially configuring logins.
func ParseAccounts(value string) ([]Account, error) {
	if value == "" {
		value = defaultUsers
	}
	if len(value) > 16<<10 {
		return nil, errors.New("account configuration exceeds the size limit")
	}
	pairs := strings.Split(value, ",")
	if len(pairs) > 32 {
		return nil, errors.New("too many configured accounts")
	}
	var accounts []Account
	seen := map[string]bool{}
	for _, pair := range pairs {
		name, password, ok := strings.Cut(pair, ":")
		if !ok || !accountName(name) || seen[name] || password == "" || len(password) > 128 || strings.ContainsAny(password, ":\r\n\x00") {
			return nil, errors.New("invalid or duplicate configured account")
		}
		seen[name] = true
		accounts = append(accounts, Account{Name: name, Password: password})
	}
	return accounts, nil
}

// Serve completes local initialization then replaces itself with genuine sshd.
// Replacing the process, rather than merely unsetting variables, removes the
// startup credential/manifest environment from the running daemon's proc entry.
func Serve() error {
	if runtime.GOOS != "linux" || os.Getenv("SESSION_CONTAINER") != "1" {
		return errors.New("server initialization requires its configured Linux container")
	}
	if os.Geteuid() != 0 {
		return errors.New("server initialization requires container root")
	}
	accounts, err := ParseAccounts(os.Getenv("BACKEND_USERS"))
	if err != nil {
		return err
	}
	var manifest *Manifest
	if data, exists := os.LookupEnv("BACKEND_SCENE"); exists {
		m, err := DecodeManifest([]byte(data))
		if err != nil {
			return err
		}
		manifest = &m
	}
	if err := os.MkdirAll(LogDirectory, 0o751); err != nil {
		return err
	}
	// Sticky write/traverse permits accounts created later in the disposable
	// system to create their own0700 subdirectory, without listing other users.
	if err := os.Chmod(LogDirectory, os.ModeSticky|0o733); err != nil {
		return err
	}
	for _, account := range accounts {
		if _, err := user.Lookup(account.Name); err != nil {
			var unknown user.UnknownUserError
			if !errors.As(err, &unknown) {
				return fmt.Errorf("lookup configured account %q: %w", account.Name, err)
			}
			args, err := newAccountArgs(account.Name, user.LookupGroup)
			if err != nil {
				return err
			}
			if err := runLocal(nil, "/usr/sbin/useradd", args...); err != nil {
				return fmt.Errorf("create configured account %q: %w", account.Name, err)
			}
		} else if err := runLocal(nil, "/usr/sbin/usermod", "-s", loginShell, "--", account.Name); err != nil {
			return fmt.Errorf("configure account %q: %w", account.Name, err)
		}
		if err := runLocal(strings.NewReader(account.Name+":"+account.Password+"\n"), "/usr/sbin/chpasswd"); err != nil {
			return fmt.Errorf("set configured account password: %w", err)
		}
		uid, gid, err := lookupOwner(account.Name)
		if err != nil {
			return err
		}
		dir := filepath.Join(LogDirectory, "uid-"+strconv.Itoa(uid))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	if manifest != nil {
		if err := Seed("/", *manifest, lookupOwner); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil {
		return err
	}
	bootstrap, err := privateHostKeyDirectory(filepath.Dir(HostKeySourceDirectory))
	if err != nil {
		return err
	}
	if err := bootstrap.Close(); err != nil {
		return err
	}
	if err := prepareKeys(HostKeySourceDirectory); err != nil {
		return err
	}
	if err := copyPrivateHostKeys(HostKeySourceDirectory, "/run/sshd/hostkeys"); err != nil {
		return err
	}
	if err := prepareAuthLog(LogDirectory); err != nil {
		return err
	}
	// Preserve the recreation gap used by existing broker reset verification.
	time.Sleep(time.Second)
	return execDaemon("/usr/sbin/sshd", []string{"/usr/sbin/sshd", "-D", "-E", filepath.Join(LogDirectory, "sshd.log"), "-f", "/etc/ssh/sshd_config"}, FilterEnvironment(os.Environ()))
}

func prepareAuthLog(dir string) error {
	name := filepath.Join(dir, "sshd.log")
	info, err := os.Lstat(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && !info.Mode().IsRegular() {
		return errors.New("authentication log is not a regular file")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	file, err := r.OpenFile("sshd.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(file.Chown(os.Getuid(), os.Getgid()), file.Chmod(0o600), file.Close())
}

// FilterEnvironment removes bootstrap secrets before replacing the process.
func FilterEnvironment(environ []string) []string {
	filtered := make([]string, 0, len(environ))
	for _, item := range environ {
		name, _, _ := strings.Cut(item, "=")
		switch strings.ToUpper(name) {
		case "BACKEND_SCENE", "BACKEND_USERS", "SESSION_CONTAINER", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS", "DOCKER_TLS_VERIFY":
			continue
		default:
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func lookupOwner(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	return uid, gid, err
}

func runLocal(input *strings.Reader, command string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	diagnostic := &boundedDiagnostic{}
	if filepath.Base(command) != "chpasswd" {
		cmd.Stderr = diagnostic
	}
	if input != nil {
		cmd.Stdin = input
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w (%s)", command, err, strings.TrimSpace(diagnostic.String()))
	}
	return nil
}

func newAccountArgs(name string, lookup func(string) (*user.Group, error)) ([]string, error) {
	args := []string{"-m", "-s", loginShell}
	if _, err := lookup(name); err == nil {
		args = append(args, "-g", name)
	} else {
		var unknown user.UnknownGroupError
		if !errors.As(err, &unknown) {
			return nil, fmt.Errorf("lookup configured account group %q: %w", name, err)
		}
	}
	return append(args, "--", name), nil
}

type boundedDiagnostic struct{ bytes.Buffer }

func (b *boundedDiagnostic) Write(data []byte) (int, error) {
	n := len(data)
	remaining := 4096 - b.Len()
	if remaining > 0 {
		_, _ = b.Buffer.Write(data[:min(n, remaining)])
	}
	return n, nil
}

func prepareKeys(dir string) error {
	missing := false
	for _, kind := range []string{"rsa", "ecdsa", "ed25519"} {
		if _, err := os.Stat(filepath.Join(dir, "ssh_host_"+kind+"_key")); err != nil {
			missing = true
		}
	}
	if !missing {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".keygen.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		return err
	}
	for _, kind := range []string{"rsa", "ecdsa", "ed25519"} {
		key := filepath.Join(dir, "ssh_host_"+kind+"_key")
		if _, err := os.Stat(key); err == nil {
			continue
		}
		if err := runLocal(nil, "/usr/bin/ssh-keygen", "-q", "-t", kind, "-f", key, "-N", ""); err != nil {
			return err
		}
	}
	return nil
}

// copyPrivateHostKeys gives sshd private regular files even when a read-only
// desktop bind reports permissive modes. Existing source keys are never chmodded
// or replaced, preserving the shared identity across cells and restarts.
func copyPrivateHostKeys(source, destination string) error {
	const maxHostKeyBytes = 64 << 10
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !sourceInfo.IsDir() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("host key source is not an ordinary directory")
	}
	from, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer from.Close()
	keys := make(map[string][]byte, 3)
	for _, kind := range []string{"rsa", "ecdsa", "ed25519"} {
		name := "ssh_host_" + kind + "_key"
		before, err := from.Lstat(name)
		if err != nil {
			return fmt.Errorf("inspect host key %s: %w", kind, err)
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("host key %s is not a regular file", kind)
		}
		file, err := from.OpenFile(name, privateKeyReadFlags, 0)
		if err != nil {
			return fmt.Errorf("open host key %s: %w", kind, err)
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
			_ = file.Close()
			return fmt.Errorf("host key %s changed while opening: %w", kind, errors.Join(statErr, errors.New("file identity or type changed")))
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxHostKeyBytes+1))
		if err := errors.Join(readErr, file.Close()); err != nil {
			return fmt.Errorf("read host key %s: %w", kind, err)
		}
		if len(data) == 0 || len(data) > maxHostKeyBytes {
			return fmt.Errorf("host key %s is empty or exceeds the size limit", kind)
		}
		keys[name] = data
	}
	to, err := privateHostKeyDirectory(destination)
	if err != nil {
		return err
	}
	defer to.Close()
	for name, data := range keys {
		if existing, err := to.Lstat(name); err == nil && !existing.Mode().IsRegular() {
			return fmt.Errorf("private host key destination %s is not a regular file", name)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		temporary := ".hostkey-" + hex.EncodeToString(random[:])
		file, err := to.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(data)
		writeErr = errors.Join(writeErr, file.Chmod(0o600), file.Sync(), file.Close())
		if writeErr == nil {
			writeErr = to.Rename(temporary, name)
		}
		if writeErr != nil {
			_ = to.Remove(temporary)
			return fmt.Errorf("copy private host key: %w", writeErr)
		}
	}
	return nil
}

func privateHostKeyDirectory(destination string) (*os.Root, error) {
	if err := safeParents("/", destination, true); err != nil {
		return nil, fmt.Errorf("prepare private host key path: %w", err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(destination)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != os.Geteuid() {
		return nil, errors.New("private host key directory is not owned by the daemon")
	}
	to, err := os.OpenRoot(destination)
	if err != nil {
		return nil, err
	}
	directory, err := to.Open(".")
	if err != nil {
		_ = to.Close()
		return nil, err
	}
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(info, opened) || fileUID(opened) != os.Geteuid() {
		_ = directory.Close()
		_ = to.Close()
		return nil, errors.Join(err, errors.New("private host key directory changed while opening"))
	}
	if err := errors.Join(directory.Chmod(0o700), directory.Close()); err != nil {
		_ = to.Close()
		return nil, err
	}
	return to, nil
}

// Health checks the local daemon's ordinary SSH banner without authenticating.
func Health() error {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil || string(prefix[:]) != "SSH-" {
		return errors.New("SSH daemon is not ready")
	}
	return nil
}
