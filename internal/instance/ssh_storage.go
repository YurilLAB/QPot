package instance

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/proxy"
)

const sshStorePointer = ".runtime-store.json"
const sshStoreOwner = ".owner.json"

// sshRuntimeStore describes host-owned storage whose canonical names are also
// visible in a guest's genuine mountinfo. The pointer stays private in the
// instance directory; guests receive only their individual leaf directories.
type sshRuntimeStore struct {
	Version   int    `json:"version"`
	Root      string `json:"root"`
	Namespace string `json:"namespace"`
	Instance  string `json:"instance"`
	State     string `json:"state"`
	legacy    bool
	planned   bool
}

func sshStorageError(err error) error {
	return hostsetup.E("QP-INST-011").Wrap(err)
}

func canonicalSSHPath(name string) (string, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	current := absolute
	var missing []string
	for {
		_, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("cannot resolve storage parent %q", name)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func decodeSSHStore(r io.Reader) (sshRuntimeStore, error) {
	var store sshRuntimeStore
	d := json.NewDecoder(io.LimitReader(r, 16<<10))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return store, errors.New("runtime location must be one JSON object")
	}
	fields := map[string]json.RawMessage{}
	allowed := map[string]bool{"version": true, "root": true, "namespace": true, "instance": true, "state": true}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || fields[name] != nil {
			return store, errors.New("runtime location has an unknown or duplicate field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return store, err
		}
		fields[name] = value
	}
	if _, err := d.Token(); err != nil {
		return store, err
	}
	var trailing any
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return store, errors.New("runtime location has trailing data")
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return store, err
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return store, err
	}
	return store, nil
}

func readSSHStoreRecord(directory, name string) (sshRuntimeStore, error) {
	var store sshRuntimeStore
	root, err := os.OpenRoot(directory)
	if err != nil {
		return store, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return store, err
	}
	if !info.Mode().IsRegular() || !sshStoreOwned(info) || info.Size() > 16<<10 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return store, errors.New("runtime location must be a private ordinary file")
	}
	f, err := root.Open(name)
	if err != nil {
		return store, err
	}
	defer f.Close()
	return decodeSSHStore(f)
}

func validSSHNamespace(namespace string) bool {
	if len(namespace) != 64 {
		return false
	}
	for _, b := range namespace {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func validateSSHStore(store sshRuntimeStore, dataPath string) error {
	instancePath, err := canonicalSSHPath(dataPath)
	if err != nil {
		return err
	}
	if store.Version != 1 || !validSSHNamespace(store.Namespace) || store.Instance != instancePath ||
		(store.State != "migrating" && store.State != "ready") || !filepath.IsAbs(store.Root) ||
		filepath.Clean(store.Root) != store.Root || filepath.Base(store.Root) != sshStoreDirectory(store.Namespace) ||
		filepath.Base(filepath.Dir(store.Root)) != "session-store" {
		return errors.New("runtime location does not belong to this instance")
	}
	canonical, err := canonicalSSHPath(store.Root)
	if err != nil || canonical != store.Root {
		return errors.New("runtime location has a changed or symbolic-link ancestor")
	}
	info, err := os.Lstat(store.Root)
	if err != nil || !info.IsDir() || !sshStoreOwned(info) || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("runtime store is missing or is not a private ordinary directory")
	}
	for current := filepath.Dir(store.Root); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || !sshStoreSafeAncestor(info) {
			return errors.New("runtime store has an unsafe ownership or writable ancestor")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	parentInfo, err := os.Lstat(filepath.Dir(store.Root))
	if err != nil || !sshStoreOwned(parentInfo) || runtime.GOOS != "windows" && parentInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("runtime store parent is not private and owned")
	}
	owner, err := readSSHStoreRecord(store.Root, sshStoreOwner)
	if err != nil || owner.Version != store.Version || owner.Root != store.Root || owner.Namespace != store.Namespace || owner.Instance != store.Instance ||
		(owner.State != "migrating" && owner.State != "ready") || (store.State == "ready" && owner.State != "ready") {
		return errors.New("runtime ownership record is missing or does not match this instance")
	}
	return nil
}

func sshStoreAt(dataPath string) (sshRuntimeStore, error) {
	store, err := readSSHStoreRecord(dataPath, sshStorePointer)
	if errors.Is(err, os.ErrNotExist) {
		return sshRuntimeStore{Root: dataPath, Instance: dataPath, legacy: true}, nil
	}
	if err != nil {
		return store, sshStorageError(err)
	}
	if err := validateSSHStore(store, dataPath); err != nil {
		return store, sshStorageError(err)
	}
	return store, nil
}

// planSSHStore never creates files. A missing ID is allowed for a dry plan;
// reservation replaces that public fallback with randomness and rerenders
// before a guest can start. Normal CLI instances already have a random QPot ID.
func planSSHStore(cfg *config.Config) (sshRuntimeStore, error) {
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil || !store.legacy {
		return store, err
	}
	instancePath, err := canonicalSSHPath(cfg.DataPath)
	if err != nil {
		return store, sshStorageError(err)
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return store, sshStorageError(homeErr)
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	if !filepath.IsAbs(dataHome) {
		return store, sshStorageError(errors.New("XDG_DATA_HOME must be absolute for persistent runtime storage"))
	}
	dataHome, err = canonicalSSHPath(dataHome)
	if err != nil {
		return store, sshStorageError(err)
	}
	mac := hmac.New(sha256.New, []byte(cfg.QPotID))
	_, _ = mac.Write([]byte("session-store-v1\x00" + instancePath))
	namespace := hex.EncodeToString(mac.Sum(nil))
	return sshRuntimeStore{Version: 1, Root: filepath.Join(dataHome, "session-store", sshStoreDirectory(namespace)), Namespace: namespace,
		Instance: instancePath, State: "migrating", planned: true}, nil
}

func (s sshRuntimeStore) slot(service string) string {
	if s.legacy {
		return service
	}
	return proxy.ContextStorageName(s.Namespace, service)
}

func (s sshRuntimeStore) area() string {
	if s.legacy {
		return filepath.Join(s.Root, "honeypots", sshProxyHoneypot)
	}
	return filepath.Join(s.Root, "records")
}

func (s sshRuntimeStore) current(service string) string {
	return filepath.Join(s.area(), "logs", "cells", s.slot(service), "current")
}

func (s sshRuntimeStore) contextRoot() string {
	if s.legacy {
		return filepath.Join(s.Root, "hifi-contexts")
	}
	return filepath.Join(s.Root, "contexts")
}

func (s sshRuntimeStore) context(service string) string {
	return filepath.Join(s.contextRoot(), s.slot(service))
}

func (s sshRuntimeStore) keys(backup bool) string {
	leaf := "shared-hostkeys"
	if backup {
		leaf = "backup-hostkeys"
	}
	if s.legacy {
		return filepath.Join(s.Root, "honeypots", sshBackendDataDir, leaf)
	}
	return filepath.Join(s.Root, "identities", leaf)
}

func (s sshRuntimeStore) database(service string) string {
	if s.legacy {
		return filepath.Join(s.Root, "honeypots", sshBackendDataDir, service, "db-init.sql")
	}
	return filepath.Join(s.Root, "bootstrap", s.slot(service)+".sql")
}

func writeSSHStoreRecord(directory, name string, store sshRuntimeStore) error {
	data, err := json.Marshal(store)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	if info, err := root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return errors.New("runtime ownership target is not an ordinary file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := ".location-" + rand.Text()
	f, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = root.Remove(temporary) }()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	return syncSSHDirectory(directory)
}

// prepareSSHStore runs with the lifecycle lock held after every old cell has
// stopped. Migration never reads visitor files: same-filesystem renames retain
// ownership, symlinks and checkpoint identities. Partial renames are resumable.
func prepareSSHStore(cfg *config.Config) (bool, error) {
	store, err := planSSHStore(cfg)
	if err != nil {
		return false, err
	}
	changedPlan := false
	if store.planned && cfg.QPotID == "" {
		var id [32]byte
		if _, err := rand.Read(id[:]); err != nil {
			return false, sshStorageError(err)
		}
		store.Namespace = hex.EncodeToString(id[:])
		store.Root = filepath.Join(filepath.Dir(store.Root), sshStoreDirectory(store.Namespace))
		changedPlan = true
	}
	if store.planned {
		dataHome := filepath.Dir(filepath.Dir(store.Root))
		if err := os.MkdirAll(dataHome, 0o700); err != nil {
			return false, sshStorageError(err)
		}
		homeRoot, err := os.OpenRoot(dataHome)
		if err != nil {
			return false, sshStorageError(err)
		}
		defer homeRoot.Close()
		if err := homeRoot.Mkdir("session-store", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return false, sshStorageError(err)
		}
		info, err := homeRoot.Lstat("session-store")
		if err != nil || !info.IsDir() || !sshStoreOwned(info) || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return false, sshStorageError(errors.New("session-store parent is not a private ordinary directory"))
		}
		stores, err := homeRoot.OpenRoot("session-store")
		if err != nil {
			return false, sshStorageError(err)
		}
		defer stores.Close()
		if err := stores.Mkdir(filepath.Base(store.Root), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return false, sshStorageError(err)
		}
		info, err = stores.Lstat(filepath.Base(store.Root))
		if err != nil || !info.IsDir() || !sshStoreOwned(info) || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return false, sshStorageError(errors.New("runtime destination is not a private ordinary directory"))
		}
		if _, err := os.Lstat(filepath.Join(store.Root, sshStoreOwner)); errors.Is(err, os.ErrNotExist) {
			dir, openErr := os.Open(store.Root)
			if openErr != nil {
				return false, sshStorageError(openErr)
			}
			names, readErr := dir.Readdirnames(1)
			_ = dir.Close()
			if len(names) != 0 || readErr != nil && !errors.Is(readErr, io.EOF) {
				return false, sshStorageError(errors.New("planned runtime destination already contains unowned data"))
			}
			if err := writeSSHStoreRecord(store.Root, sshStoreOwner, store); err != nil {
				return false, sshStorageError(err)
			}
		}
		if err := validateSSHStore(store, cfg.DataPath); err != nil {
			return false, sshStorageError(err)
		}
		if err := syncSSHDirectory(filepath.Dir(store.Root)); err != nil {
			return false, sshStorageError(err)
		}
		if err := syncSSHDirectory(dataHome); err != nil {
			return false, sshStorageError(err)
		}
		if err := writeSSHStoreRecord(cfg.DataPath, sshStorePointer, store); err != nil {
			return false, sshStorageError(err)
		}
	}
	if store.State == "ready" {
		return changedPlan, nil
	}
	if err := migrateSSHStore(cfg.DataPath, store); err != nil {
		return false, sshStorageError(err)
	}
	store.State = "ready"
	if err := writeSSHStoreRecord(store.Root, sshStoreOwner, store); err != nil {
		return false, sshStorageError(err)
	}
	if err := writeSSHStoreRecord(cfg.DataPath, sshStorePointer, store); err != nil {
		return false, sshStorageError(err)
	}
	return changedPlan, nil
}

func renameSSHStorage(source, target string) error {
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("legacy runtime root is not an ordinary file or directory: %s", source)
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("both legacy and neutral runtime paths exist; preserve and inspect %q and %q before retrying", source, target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		return fmt.Errorf("move stopped runtime data from %q to %q without changing its bytes (different filesystems require an offline ownership-preserving move): %w", source, target, err)
	}
	if err := syncSSHDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	return syncSSHDirectory(filepath.Dir(source))
}

func migrateSSHStore(dataPath string, store sshRuntimeStore) error {
	legacy := sshRuntimeStore{Root: dataPath, legacy: true}
	move := func(source, target string) error {
		if err := safeSSHLegacyPath(dataPath, source); err != nil {
			return err
		}
		rel, err := filepath.Rel(store.Root, filepath.Dir(target))
		if err != nil || !filepath.IsLocal(rel) {
			return errors.New("runtime destination escaped its private root")
		}
		if err := ensureSSHStoreDirectories(store.Root, rel); err != nil {
			return err
		}
		return renameSSHStorage(source, target)
	}
	// The destination is reserved before the first move, so an interrupted
	// migration resumes the same namespace even after environment changes.
	for _, backup := range []bool{false, true} {
		if err := move(legacy.keys(backup), store.keys(backup)); err != nil {
			return err
		}
	}
	for _, service := range SSHCellLogServices() {
		if err := move(filepath.Dir(legacy.current(service)), filepath.Dir(store.current(service))); err != nil {
			return err
		}
		// Very old layouts stored recordings beside host keys. Preserve the
		// entire stopped tree by rename, without opening attacker files.
		oldRecordings := filepath.Join(dataPath, "honeypots", sshBackendDataDir, service, "logs")
		if err := safeSSHLegacyPath(dataPath, oldRecordings); err != nil {
			return err
		}
		if info, err := os.Lstat(oldRecordings); err == nil {
			if !info.IsDir() {
				return errors.New("legacy recordings must be an ordinary directory")
			}
			parent := filepath.Dir(store.current(service))
			rel, err := filepath.Rel(store.Root, parent)
			if err != nil || !filepath.IsLocal(rel) {
				return errors.New("legacy archive escaped store")
			}
			if err := ensureSSHStoreDirectories(store.Root, rel); err != nil {
				return err
			}
			archive, err := os.MkdirTemp(parent, "archive-g0-")
			if err != nil {
				return err
			}
			if err := move(oldRecordings, filepath.Join(archive, "logs")); err != nil {
				_ = os.Remove(archive)
				return err
			}
			// This timestamp belongs to the trusted archive header.
			stamp := time.Now()
			if err := os.Chtimes(archive, stamp, stamp); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if service == sshCellApp(service) {
			if err := move(legacy.context(service), store.context(service)); err != nil {
				return err
			}
			if err := move(legacy.database(service), store.database(service)); err != nil {
				return err
			}
		}
	}
	// Older layouts wrote the broker directly below logs; retain every entry
	// without opening it, while the old broker and cells are stopped.
	oldLogs := filepath.Join(legacy.area(), "logs")
	directory, err := os.Open(oldLogs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	// This parent is host owned, but bound metadata work for restored data.
	budget := 8192
	for budget > 0 {
		entries, readErr := directory.ReadDir(min(budget, 256))
		budget -= len(entries)
		for _, entry := range entries {
			if entry.Name() == "cells" {
				continue
			}
			if err := move(filepath.Join(oldLogs, entry.Name()), filepath.Join(store.area(), "logs", entry.Name())); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
	return errors.New("legacy broker metadata exceeds migration entry limit; inspect the stopped log directory before retrying")
}

func safeSSHLegacyPath(dataPath, source string) error {
	rel, err := filepath.Rel(dataPath, source)
	if err != nil || !filepath.IsLocal(rel) {
		return errors.New("legacy runtime source escaped its instance")
	}
	root, err := os.OpenRoot(dataPath)
	if err != nil {
		return err
	}
	defer root.Close()
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for index := range parts {
		info, err := root.Lstat(filepath.Join(parts[:index+1]...))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || index < len(parts)-1 && !info.IsDir() {
			return errors.New("legacy runtime root has a symbolic-link or non-directory ancestor")
		}
	}
	return nil
}

func ensureSSHStoreDirectories(directory, rel string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for index := range parts {
		part := filepath.Join(parts[:index+1]...)
		info, err := root.Lstat(part)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(part, 0o750); err != nil {
				return err
			}
			continue
		}
		if err != nil || !info.IsDir() {
			return errors.New("runtime storage has a symbolic-link or non-directory ancestor")
		}
	}
	return nil
}

// prepareSSHRuntimeLayout is called only with the lifecycle lock held and
// after the complete candidate Compose has passed validation. It stops the old
// finite layout before reserving or moving a single runtime directory.
func prepareSSHRuntimeLayout(ctx context.Context, cfg *config.Config) error {
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		return err
	}
	if !sshProxyEnabled(cfg) && store.legacy {
		return nil
	}
	if !store.legacy && store.State == "ready" {
		return nil
	}
	layout, err := readSSHLayout(cfg.GetDockerComposePath(), cfg.InstanceName)
	if err != nil {
		return err
	}
	var services []string
	if layout.Broker {
		services = append(services, sshProxyHoneypot)
	}
	for _, members := range layout.Groups {
		services = append(services, members...)
	}
	if len(services) == 0 {
		legacy := sshRuntimeStore{Root: cfg.DataPath, legacy: true}
		for _, candidate := range []string{legacy.keys(false), legacy.keys(true), filepath.Join(cfg.DataPath, "honeypots", sshBackendDataDir), legacy.contextRoot(), filepath.Join(legacy.area(), "logs", "cells"), filepath.Join(legacy.area(), "logs", "broker")} {
			if _, statErr := os.Lstat(candidate); statErr == nil {
				return sshStorageError(errors.New("existing SSH runtime data has no owned prior Compose layout; restore that layout and stop its cells before migration"))
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return sshStorageError(statErr)
			}
		}
		directory, openErr := os.Open(filepath.Join(legacy.area(), "logs"))
		if openErr == nil {
			names, readErr := directory.Readdirnames(1)
			_ = directory.Close()
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return sshStorageError(readErr)
			}
			if len(names) > 0 {
				return sshStorageError(errors.New("existing broker records have no owned prior Compose layout; restore the layout and stop it before migration"))
			}
		} else if !errors.Is(openErr, os.ErrNotExist) {
			return sshStorageError(openErr)
		}
	}
	if err := stopSSHServices(ctx, cfg.GetDockerComposePath(), services); err != nil {
		return err
	}
	_, err = prepareSSHStore(cfg)
	return err
}

// SSHRuntimeLogArea is the logical ssh-proxy retention area, including closed
// evidence. Existing instances keep their legacy area until stopped migration.
func SSHRuntimeLogArea(cfg *config.Config) (string, error) {
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		return "", err
	}
	return store.area(), nil
}

// SSHRuntimeCellID maps a finite service to its canonical storage leaf while
// keeping service names in collector events and the operator-facing API.
func SSHRuntimeCellID(dataPath, service string) (string, error) {
	if sshCellApp(service) == "" {
		return "", sshStorageError(errors.New("unknown runtime service"))
	}
	store, err := sshStoreAt(dataPath)
	if err != nil {
		return "", err
	}
	return store.slot(service), nil
}

func validateSSHStorePlan(cfg *config.Config) error {
	if !sshProxyEnabled(cfg) {
		_, err := sshStoreAt(cfg.DataPath)
		return err
	}
	_, err := planSSHStore(cfg)
	return err
}

func sshStoreNamespace(cfg *config.Config) (string, error) {
	store, err := planSSHStore(cfg)
	return store.Namespace, err
}

func sshStoreContextRoot(cfg *config.Config) (string, error) {
	store, err := planSSHStore(cfg)
	return store.contextRoot(), err
}

func sshStoreContext(cfg *config.Config, service string) (string, error) {
	store, err := planSSHStore(cfg)
	return store.context(service), err
}

func sshStoreSharedKeys(cfg *config.Config) (string, error) {
	store, err := planSSHStore(cfg)
	return store.keys(false), err
}

func sshStoreRecordRoot(cfg *config.Config) (string, error) {
	store, err := planSSHStore(cfg)
	return filepath.Join(store.area(), "logs"), err
}

func sshStoreReady(dataPath string) error {
	store, err := sshStoreAt(dataPath)
	if err != nil {
		return err
	}
	if store.legacy || store.State != "ready" {
		return sshStorageError(errors.New("runtime storage migration has not completed; initialize this instance before starting its SSH cells"))
	}
	return nil
}

func neutralSSHComponent(name string) bool {
	name = strings.ToLower(name)
	return !strings.Contains(name, "qpot") && !strings.Contains(name, "honeypot")
}

// removeSSHStore is called only after a successful stop, with the lifecycle
// lock held. Both private ownership records must still agree. The os.Root
// parent prevents removing anything outside the derived instance leaf.
func removeSSHStore(ctx context.Context, dataPath string) error {
	store, err := sshStoreAt(dataPath)
	if err != nil {
		return err
	}
	if store.legacy {
		return nil
	}
	parent, err := os.OpenRoot(filepath.Dir(store.Root))
	if err != nil {
		return sshStorageError(err)
	}
	defer parent.Close()
	info, err := parent.Lstat(filepath.Base(store.Root))
	if err != nil || !info.IsDir() {
		return sshStorageError(errors.New("runtime store changed before removal"))
	}
	owner, err := readSSHStoreRecord(store.Root, sshStoreOwner)
	if err != nil || owner.Root != store.Root || owner.Namespace != store.Namespace || owner.Instance != store.Instance {
		return sshStorageError(errors.New("runtime ownership changed before removal"))
	}
	owned, err := parent.OpenRoot(filepath.Base(store.Root))
	if err != nil {
		return sshStorageError(err)
	}
	defer owned.Close()
	// Delete guest-owned recordings first, retaining both ownership records
	// until every inaccessible private directory has really been removed.
	if err := owned.RemoveAll("records"); err != nil {
		records := store.area()
		if info, statErr := owned.Lstat("records"); statErr != nil || !info.IsDir() {
			return sshStorageError(errors.New("record root changed before removal"))
		}
		if strings.ContainsAny(records, ",\n\x00") {
			return sshStorageError(errors.New("record root cannot be safely mounted for cleanup"))
		}
		helperCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		out, helperErr := exec.CommandContext(helperCtx, "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m", "--user", "0:0", "--mount", "type=bind,source="+records+",target=/c", "--entrypoint", "rm", ownershipHelperImage, "-rf", "--", "/c/logs").CombinedOutput()
		cancel()
		if helperErr != nil {
			return sshStorageError(fmt.Errorf("remove stopped private recording files: %w: %.300s", helperErr, out))
		}
		if err := owned.RemoveAll("records"); err != nil {
			return sshStorageError(err)
		}
	}
	for _, area := range []string{"contexts", "identities", "bootstrap"} {
		if err := owned.RemoveAll(area); err != nil {
			return sshStorageError(err)
		}
	}
	// Only generated, host-owned entries remain. Remove the marker last so a
	// permission/IO failure above remains safely retryable.
	dir, err := owned.Open(".")
	if err != nil {
		return sshStorageError(err)
	}
	names, err := dir.Readdirnames(2)
	_ = dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return sshStorageError(err)
	}
	if len(names) != 1 || names[0] != sshStoreOwner {
		return sshStorageError(errors.New("unexpected runtime entries remain; inspect before removing this store"))
	}
	if err := owned.Remove(sshStoreOwner); err != nil {
		return sshStorageError(err)
	}
	// Windows may deny deleting a directory while its handle is held.
	if err := owned.Close(); err != nil {
		return sshStorageError(err)
	}
	if err := parent.Remove(filepath.Base(store.Root)); err != nil {
		// An external file lock/IO failure must not strand an otherwise
		// verified empty root without the marker needed for a safe retry.
		current, statErr := parent.Lstat(filepath.Base(store.Root))
		if statErr == nil && current.IsDir() && os.SameFile(info, current) {
			err = errors.Join(err, writeSSHStoreRecord(store.Root, sshStoreOwner, store))
		}
		return sshStorageError(err)
	}
	return syncSSHDirectory(filepath.Dir(store.Root))
}

// SSHRuntimeStorageRoot locates persistent runtime data for backup/diagnostics.
// A missing location record returns the existing instance path; it never
// reserves a new location or changes the running instance.
func SSHRuntimeStorageRoot(cfg *config.Config) (string, error) {
	store, err := sshStoreAt(cfg.DataPath)
	return store.Root, err
}

func syncSSHDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// A guest sees the canonical root basename. Keep the MAC key private so that
// seeing that public ID does not permit a finite service-name dictionary test
// against the opaque per-cell leaves. Only the trusted broker gets Namespace.
func sshStoreDirectory(namespace string) string {
	sum := sha256.Sum256([]byte("session-root-v1\x00" + namespace))
	return hex.EncodeToString(sum[:])
}

// Only a committed, verified private host store may opt its trusted broker
// metadata into a host-readable mode. Dry/legacy/pending plans keep the custom
// broker default; the post-migration pinned render selects this after ready.
func sshBrokerHostReadable(cfg *config.Config) (bool, error) {
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		return false, err
	}
	return !store.legacy && store.State == "ready", nil
}
