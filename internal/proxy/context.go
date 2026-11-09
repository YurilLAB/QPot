package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// ContextStorageName gives a backend a per-instance opaque host directory.
// Callers validate backend IDs before using the legacy empty namespace form.
func ContextStorageName(namespace, backendID string) string {
	if namespace == "" {
		return backendID
	}
	mac := hmac.New(sha256.New, []byte(namespace))
	_, _ = mac.Write([]byte("slot\x00" + backendID))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// ValidateContextNamespace accepts the legacy layout or one full namespace ID.
func ValidateContextNamespace(namespace string) error {
	if namespace == "" || len(namespace) == 64 && validSessionID(namespace[:32]) && validSessionID(namespace[32:]) {
		return nil
	}
	return errors.New("context namespace must be one lowercase256-bit identifier")
}

// ConnectionContext carries the broker's trusted transport attribution to this
// lease's app and backup recorders. Each guest receives only its own cell's
// read-only directory; neither credentials nor other cells' addresses appear.
type ConnectionContext struct {
	SessionID  string  `json:"session_id"`
	SrcIP      string  `json:"src_ip"`
	SrcPort    int     `json:"src_port"`
	StartedAt  string  `json:"started_at"`
	Generation *uint64 `json:"generation"`
}

func newSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, ch := range id {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

// writeConnectionContext publishes one complete document before the broker can
// dial its guest. Root-relative file operations confine every name to the
// operator-configured context root; backend IDs can name only one directory.
func writeConnectionContext(directory, backendID string, connection ConnectionContext, namespaces ...string) error {
	if !validBackendID(backendID) {
		return errors.New("invalid backend context id")
	}
	if len(namespaces) > 1 {
		return errors.New("only one context namespace is supported")
	}
	namespace := ""
	if len(namespaces) == 1 {
		namespace = namespaces[0]
	}
	if err := ValidateContextNamespace(namespace); err != nil {
		return err
	}
	slotName := ContextStorageName(namespace, backendID)
	if !validSessionID(connection.SessionID) || net.ParseIP(connection.SrcIP) == nil ||
		connection.SrcPort < 1 || connection.SrcPort > 65535 || connection.Generation == nil {
		return errors.New("invalid connection attribution")
	}
	if _, err := time.Parse(time.RFC3339Nano, connection.StartedAt); err != nil {
		return fmt.Errorf("invalid connection start time: %w", err)
	}
	data, err := json.Marshal(connection)
	if err != nil || len(data) > 4096 {
		return errors.New("connection attribution exceeds its size bound")
	}
	data = append(data, '\n')
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open context root: %w", err)
	}
	defer root.Close()
	created := false
	if err := root.Mkdir(slotName, 0o755); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("prepare context slot: %w", err)
	}
	info, err := root.Lstat(slotName)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("context slot is not an ordinary directory")
	}
	if created {
		// A restrictive inherited umask must not make the own-cell read-only
		// mount inaccessible to the guest's unprivileged login accounts.
		if err := root.Chmod(slotName, 0o755); err != nil {
			return fmt.Errorf("prepare context slot permissions: %w", err)
		}
	} else if info.Mode().Perm()&0o001 == 0 {
		// The slot is mounted directly into guests with different login UIDs.
		// A broker-readable but private slot would silently lose attribution.
		return errors.New("context slot is not traversable by guest login accounts")
	}
	slot, err := root.OpenRoot(slotName)
	if err != nil {
		return fmt.Errorf("open context slot: %w", err)
	}
	defer slot.Close()
	if target, err := slot.Lstat("connection.json"); err == nil {
		if !target.Mode().IsRegular() {
			return errors.New("connection context target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect connection context: %w", err)
	}
	temporary := ".connection-" + connection.SessionID + ".tmp"
	file, err := slot.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create connection context: %w", err)
	}
	defer func() {
		_ = file.Close()
		_ = slot.Remove(temporary)
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write connection context: %w", err)
	}
	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf("set connection context permissions: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync connection context: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close connection context: %w", err)
	}
	if err := slot.Rename(temporary, "connection.json"); err != nil {
		return fmt.Errorf("publish connection context: %w", err)
	}
	return nil
}
