package sshbackend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// HostKeyDirectory is where Debian keeps sshd's host keys; sshd's default
	// HostKey paths read them there, so the configuration names none.
	HostKeyDirectory = "/etc/ssh"
	defaultUsers     = "admin:admin,ubuntu:ubuntu,user:password,root:root123"
	// Accounts get the system's ordinary shell: sshd itself records sessions,
	// so nothing in the guest stands between the visitor and bash.
	loginShell = "/bin/bash"
	// HostKeysVariable carries the pool's shared host keys, so no host folder
	// is mounted into the guest (a mount shows its host path in mountinfo).
	HostKeysVariable = "BACKEND_HOST_KEYS"
)

var hostKeyKinds = []string{"rsa", "ecdsa", "ed25519"}

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
// It also deletes its own program first: once sshd runs, nothing in the guest
// is QPot's.
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
	keys, err := ParseHostKeys(os.Getenv(HostKeysVariable))
	if err != nil {
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
	}
	if manifest != nil {
		if err := Seed("/", *manifest, lookupOwner); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil {
		return err
	}
	if keys == nil {
		// A standalone image run: a key pool of its own.
		if keys, err = generateHostKeys(); err != nil {
			return err
		}
	}
	if err := writeHostKeys(HostKeyDirectory, keys, derivePublicKey); err != nil {
		return err
	}
	if err := removeSelf(); err != nil {
		return err
	}
	// Preserve the recreation gap used by existing broker reset verification.
	time.Sleep(time.Second)
	// -e: sshd's own log goes to the container's error stream, its session
	// capture to its output stream; both leave the guest through Docker.
	return execDaemon("/usr/sbin/sshd", []string{"/usr/sbin/sshd", "-D", "-e"}, FilterEnvironment(os.Environ()))
}

// removeSelf deletes this program, and its folder when that is left empty.
func removeSelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.Remove(self); err != nil {
		return fmt.Errorf("remove the bootstrap program: %w", err)
	}
	_ = os.Remove(filepath.Dir(self)) // only succeeds when empty
	return nil
}

// FilterEnvironment removes bootstrap secrets before replacing the process.
func FilterEnvironment(environ []string) []string {
	filtered := make([]string, 0, len(environ))
	for _, item := range environ {
		name, _, _ := strings.Cut(item, "=")
		switch strings.ToUpper(name) {
		case "BACKEND_SCENE", "BACKEND_USERS", HostKeysVariable, "SESSION_CONTAINER", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS", "DOCKER_TLS_VERIFY":
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

// ParseHostKeys decodes the shared host keys handed over as
// "rsa:<base64>,ecdsa:<base64>,ed25519:<base64>". An empty value means none.
func ParseHostKeys(value string) (map[string][]byte, error) {
	const maxHostKeyBytes = 64 << 10
	if value == "" {
		return nil, nil
	}
	if len(value) > 3*(maxHostKeyBytes*4/3+16) {
		return nil, errors.New("host key configuration exceeds the size limit")
	}
	keys := map[string][]byte{}
	for _, item := range strings.Split(value, ",") {
		kind, encoded, ok := strings.Cut(item, ":")
		if !ok || !slices.Contains(hostKeyKinds, kind) || keys[kind] != nil {
			return nil, errors.New("invalid or duplicate host key entry")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(data) == 0 || len(data) > maxHostKeyBytes ||
			!bytes.HasPrefix(data, []byte("-----BEGIN ")) || !bytes.Contains(data, []byte("PRIVATE KEY-----")) {
			return nil, fmt.Errorf("host key %s is not a private key", kind)
		}
		keys[kind] = data
	}
	for _, kind := range hostKeyKinds {
		if keys[kind] == nil {
			return nil, fmt.Errorf("host key %s is missing", kind)
		}
	}
	return keys, nil
}

func generateHostKeys() (map[string][]byte, error) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	keys := map[string][]byte{}
	for _, kind := range hostKeyKinds {
		key := filepath.Join(dir, "ssh_host_"+kind+"_key")
		if err := runLocal(nil, "/usr/bin/ssh-keygen", "-q", "-t", kind, "-f", key, "-N", ""); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(key)
		if err != nil {
			return nil, err
		}
		keys[kind] = data
	}
	return keys, nil
}

// writeHostKeys installs the host keys the way Debian's own package leaves
// them: each private key root's alone (sshd refuses one others may read) and
// its public half beside it, readable by all. The directory keeps its mode.
func writeHostKeys(destination string, keys map[string][]byte, public func(string) ([]byte, error)) error {
	to, err := hostKeyDirectory(destination)
	if err != nil {
		return err
	}
	defer to.Close()
	for _, kind := range hostKeyKinds {
		name := "ssh_host_" + kind + "_key"
		if err := replaceFile(to, name, keys[kind], 0o600); err != nil {
			return fmt.Errorf("write private host key: %w", err)
		}
		derived, err := public(filepath.Join(destination, name))
		if err != nil {
			return fmt.Errorf("derive public host key: %w", err)
		}
		if err := replaceFile(to, name+".pub", derived, 0o644); err != nil {
			return fmt.Errorf("write public host key: %w", err)
		}
	}
	return nil
}

// replaceFile writes a regular file atomically, refusing to follow or replace
// anything that is not a regular file.
func replaceFile(to *os.Root, name string, data []byte, mode os.FileMode) error {
	if existing, err := to.Lstat(name); err == nil && !existing.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
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
	writeErr = errors.Join(writeErr, file.Chmod(mode), file.Sync(), file.Close())
	if writeErr == nil {
		writeErr = to.Rename(temporary, name)
	}
	if writeErr != nil {
		_ = to.Remove(temporary)
	}
	return writeErr
}

// derivePublicKey reads a private key's public half with OpenSSH's own tool.
func derivePublicKey(private string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-y", "-f", private)
	diagnostic := &boundedDiagnostic{}
	cmd.Stderr = diagnostic
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ssh-keygen: %w (%s)", err, strings.TrimSpace(diagnostic.String()))
	}
	if len(out) == 0 || len(out) > 16<<10 || bytes.Count(out, []byte("\n")) != 1 || out[len(out)-1] != '\n' {
		return nil, errors.New("ssh-keygen printed no single public key")
	}
	return out, nil
}

// hostKeyDirectory opens the root-owned host key directory without changing
// its mode, refusing a symlink or a directory anyone else owns.
func hostKeyDirectory(destination string) (*os.Root, error) {
	if err := safeParents("/", destination, true); err != nil {
		return nil, fmt.Errorf("prepare host key path: %w", err)
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return nil, err
	}
	info, err := os.Lstat(destination)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("host key directory is not the daemon's own")
	}
	to, err := os.OpenRoot(destination)
	if err != nil {
		return nil, err
	}
	opened, err := to.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = to.Close()
		return nil, errors.Join(err, errors.New("host key directory changed while opening"))
	}
	return to, nil
}
