package instance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/proxy"
	"gopkg.in/yaml.v3"
)

func unreservedSSHStoreConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cfg := config.Default("storage")
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	cfg.QPotID = "qp_7d36283d8aee4fb8b4870832c32a9cc8"
	enableOnly(cfg, sshProxyHoneypot)
	return cfg
}

func storageWrite(t *testing.T, name string, data []byte, mode os.FileMode) os.FileInfo {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, mode); err != nil {
		t.Fatal(err)
	}
	// Capture identity eagerly before a migration can rename this path.
	// Windows path-based Stat otherwise defers file-ID lookup until SameFile.
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	info, statErr := file.Stat()
	if err := errors.Join(statErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	return info
}

func TestSSHStorePlanningIsPureAndReservationIsPinned(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	planned, err := planSSHStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !validSSHNamespace(planned.Namespace) || !neutralSSHComponent(planned.Root) || strings.Contains(planned.current("ssh-backend-1"), "ssh-backend") {
		t.Fatal("planned source leaks generated product or service names")
	}
	_ = renderComposeCfg(t, cfg)
	if _, err := os.Lstat(filepath.Join(cfg.DataPath, sshStorePointer)); !os.IsNotExist(err) {
		t.Fatal("dry render reserved location")
	}
	if _, err := os.Lstat(planned.Root); !os.IsNotExist(err) {
		t.Fatal("dry render created external root")
	}
	prepareSSHStoreForTest(t, cfg)
	stored, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Root != planned.Root || stored.State != "ready" {
		t.Fatal("reservation changed valid planned identity")
	}
	cfg.QPotID = "qp_rotated"
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	after, err := planSSHStore(cfg)
	if err != nil || after.Root != stored.Root || after.Namespace != stored.Namespace {
		t.Fatalf("location changed after environment/ID rotation: %+v %v", after, err)
	}
	if stored.slot("ssh-backend-1") == stored.slot("ssh-backend-1-db") {
		t.Fatal("roles share storage")
	}
}

func TestSSHStoreMigrationPreservesKeysRecordsContextsAndInodes(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	old := sshRuntimeStore{Root: cfg.DataPath, legacy: true}
	planned, err := planSSHStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pairs := [][2]string{
		{filepath.Join(old.keys(false), "ssh_host_ed25519_key"), filepath.Join(planned.keys(false), "ssh_host_ed25519_key")},
		{filepath.Join(old.keys(true), "ssh_host_ed25519_key"), filepath.Join(planned.keys(true), "ssh_host_ed25519_key")},
		{filepath.Join(old.current("ssh-backend-1"), "1001/events.json"), filepath.Join(planned.current("ssh-backend-1"), "1001/events.json")},
		{filepath.Join(filepath.Dir(old.current("ssh-backend-1")), "archive-g1-123/logs/events.json"), filepath.Join(filepath.Dir(planned.current("ssh-backend-1")), "archive-g1-123/logs/events.json")},
		{filepath.Join(old.context("ssh-backend-1"), "connection.json"), filepath.Join(planned.context("ssh-backend-1"), "connection.json")},
		{old.database("ssh-backend-1"), planned.database("ssh-backend-1")},
		{filepath.Join(old.area(), "logs/broker/leases.json"), filepath.Join(planned.area(), "logs/broker/leases.json")},
	}
	before := make([]os.FileInfo, len(pairs))
	for i, pair := range pairs {
		before[i] = storageWrite(t, pair[0], []byte("preserved\n"), 0o600)
	}
	legacyRecord := filepath.Join(cfg.DataPath, "honeypots", sshBackendDataDir, "ssh-backend-2", "logs", "legacy.json")
	legacyInfo := storageWrite(t, legacyRecord, []byte("legacy\n"), 0o640)
	prepareSSHStoreForTest(t, cfg)
	for i, pair := range pairs {
		after, err := os.Stat(pair[1])
		if err != nil || !os.SameFile(before[i], after) || after.Mode().Perm() != before[i].Mode().Perm() {
			t.Fatalf("migration replaced inode/permissions: %s %v", pair[1], err)
		}
		data, err := os.ReadFile(pair[1])
		if err != nil || string(data) != "preserved\n" {
			t.Fatal("migration changed bytes")
		}
		if _, err := os.Lstat(pair[0]); !os.IsNotExist(err) {
			t.Fatal("legacy file remains ambiguous")
		}
	}
	archives, err := filepath.Glob(filepath.Join(filepath.Dir(planned.current("ssh-backend-2")), "archive-g0-*", "logs", "legacy.json"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("old recording not preserved: %v %v", archives, err)
	}
	after, err := os.Stat(archives[0])
	if err != nil || !os.SameFile(legacyInfo, after) {
		t.Fatal("legacy recording copied instead of renamed")
	}
	prepareSSHStoreForTest(t, cfg) // ready and idempotent
}

func TestSSHStoreInterruptedMigrationResumesAndConflictFailsClosed(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	planned, err := planSSHStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(cfg.DataPath, "honeypots", sshBackendDataDir, "shared-hostkeys", "key")
	storageWrite(t, source, []byte("original"), 0o600)
	if err := os.MkdirAll(planned.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(planned.Root), 0o700); err != nil {
		t.Fatal(err)
	}
	storageWrite(t, filepath.Join(planned.Root, "unowned"), []byte("sentinel"), 0o600)
	if _, err := prepareSSHStore(cfg); err == nil {
		t.Fatal("unowned destination adopted")
	}
	if data, _ := os.ReadFile(source); string(data) != "original" {
		t.Fatal("conflict changed source")
	}
	if _, err := os.Lstat(filepath.Join(cfg.DataPath, sshStorePointer)); !os.IsNotExist(err) {
		t.Fatal("unowned destination pinned")
	}
	if err := os.Remove(filepath.Join(planned.Root, "unowned")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planned.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	// Reserve a matching interrupted marker, then simulate a completed first
	// rename. Resumption must preserve that identity and continue remaining data.
	if err := writeSSHStoreRecord(planned.Root, sshStoreOwner, planned); err != nil {
		t.Fatal(err)
	}
	if err := writeSSHStoreRecord(cfg.DataPath, sshStorePointer, planned); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(planned.keys(false)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Dir(source), planned.keys(false)); err != nil {
		t.Fatal(err)
	}
	prepareSSHStoreForTest(t, cfg)
	if data, _ := os.ReadFile(filepath.Join(planned.keys(false), "key")); string(data) != "original" {
		t.Fatal("resume regenerated key")
	}
}

func TestSSHStoreRejectsSymlinksMalformedAndForeignOwnership(t *testing.T) {
	for _, kind := range []string{"pointer-link", "root-link", "duplicate", "foreign", "writable"} {
		t.Run(kind, func(t *testing.T) {
			cfg := unreservedSSHStoreConfig(t)
			prepareSSHStoreForTest(t, cfg)
			stored, err := sshStoreAt(cfg.DataPath)
			if err != nil {
				t.Fatal(err)
			}
			pointer := filepath.Join(cfg.DataPath, sshStorePointer)
			switch kind {
			case "pointer-link":
				if runtime.GOOS == "windows" {
					t.Skip("symlink privileges")
				}
				if err := os.Rename(pointer, pointer+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(pointer+".saved", pointer); err != nil {
					t.Fatal(err)
				}
			case "root-link":
				if runtime.GOOS == "windows" {
					t.Skip("symlink privileges")
				}
				if err := os.Rename(stored.Root, stored.Root+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(stored.Root+".saved", stored.Root); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				storageWrite(t, pointer, []byte(`{"version":1,"version":1}`), 0o600)
			case "foreign":
				stored.Instance = filepath.Join(t.TempDir(), "other")
				data, _ := json.Marshal(stored)
				storageWrite(t, filepath.Join(stored.Root, sshStoreOwner), data, 0o600)
			case "writable":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX modes")
				}
				if err := os.Chmod(stored.Root, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := sshStoreAt(cfg.DataPath); err == nil || !strings.Contains(err.Error(), "QP-INST-011") {
				t.Fatalf("unsafe location accepted: %v", err)
			}
		})
	}
}

func TestSSHStoreEmptyIDReservationRerendersAndRemovalChecksOwnership(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	cfg.QPotID = ""
	planned, err := planSSHStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := prepareSSHStore(cfg)
	if err != nil || !changed {
		t.Fatalf("missing ID not privately reserved: %v", err)
	}
	stored, err := sshStoreAt(cfg.DataPath)
	if err != nil || stored.Namespace == planned.Namespace {
		t.Fatal("public dry identity became persistent identity")
	}
	// Removal fails closed if ownership metadata no longer agrees.
	foreign := stored
	foreign.Instance = "elsewhere"
	if err := writeSSHStoreRecord(stored.Root, sshStoreOwner, foreign); err != nil {
		t.Fatal(err)
	}
	if err := removeSSHStore(context.Background(), cfg.DataPath); err == nil {
		t.Fatal("foreign runtime root removed")
	}
	if err := writeSSHStoreRecord(stored.Root, sshStoreOwner, stored); err != nil {
		t.Fatal(err)
	}
	if err := removeSSHStore(context.Background(), cfg.DataPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stored.Root); !os.IsNotExist(err) {
		t.Fatal("verified runtime root remains")
	}
}

func TestSSHStoreLiveMigrationStopFailureLeavesBothRootsUntouched(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	record := organizationFakeDocker(t)
	_ = record
	// Invalid old Compose is rejected before any location reservation/move.
	storageWrite(t, cfg.GetDockerComposePath(), []byte("services: [invalid"), 0o600)
	if err := prepareSSHRuntimeLayout(context.Background(), cfg); err == nil {
		t.Fatal("invalid prior layout accepted")
	}
	if _, err := os.Lstat(filepath.Join(cfg.DataPath, sshStorePointer)); !os.IsNotExist(err) {
		t.Fatal("failed stop reserved location")
	}
}

func TestSSHStoreCrossFilesystemMigrationKeepsSourceAndReservation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bounded /dev/shm cross-filesystem fixture")
	}
	cfg := unreservedSSHStoreConfig(t)
	source := filepath.Join(cfg.DataPath, "honeypots", sshBackendDataDir, "shared-hostkeys", "key")
	storageWrite(t, source, []byte("never regenerate this identity"), 0o600)
	if info, err := os.Stat("/dev/shm"); err != nil || !info.IsDir() {
		t.Skip("no separate shared-memory filesystem")
	}
	t.Run("separate filesystem", func(t *testing.T) {
		t.Setenv("TMPDIR", "/dev/shm")
		t.Setenv("XDG_DATA_HOME", t.TempDir())
		_, err := prepareSSHStore(cfg)
		if err == nil {
			t.Skip("fixture filesystems do not differ")
		}
		var coded *hostsetup.Error
		if !errors.As(err, &coded) || coded.Code != "QP-INST-011" || !strings.Contains(coded.Details, "offline") {
			t.Fatalf("cross-filesystem refusal not actionable: %v", err)
		}
		if data, _ := os.ReadFile(source); string(data) != "never regenerate this identity" {
			t.Fatal("failed migration lost original")
		}
		stored, err := sshStoreAt(cfg.DataPath)
		if err != nil || stored.State != "migrating" {
			t.Fatalf("partial migration not pinned for recovery: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(stored.keys(false), "key")); !os.IsNotExist(err) {
			t.Fatal("cross-filesystem failure created key copy")
		}
	})
}

func FuzzSSHRuntimeLocationDecoder(f *testing.F) {
	for _, seed := range []string{`{}`, `{"version":1,"root":"/x/session-store/a","namespace":"a","instance":"/x","state":"ready"}`, `{"version":1,"version":2}`, `{"state":"ready"} trailing`, strings.Repeat("[", 64)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 32<<10 {
			return
		}
		store, err := decodeSSHStore(strings.NewReader(data))
		if err == nil {
			encoded, err := json.Marshal(store)
			if err != nil {
				t.Fatal(err)
			}
			again, err := decodeSSHStore(strings.NewReader(string(encoded)))
			if err != nil || again.Version != store.Version || again.Root != store.Root || again.Namespace != store.Namespace || again.Instance != store.Instance || again.State != store.State {
				t.Fatal("accepted location changed across canonical round trip")
			}
		}
	})
}

func TestSSHStoreCollectorMountsExposeOnlyReadOnlyRecordsAndNeverSeedNativeEvidence(t *testing.T) {
	cfg := organizationTestConfig(t)
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	current := store.current("ssh-backend-1")
	storageWrite(t, filepath.Join(current, "uid-1001", "events.json"), []byte("{\"event\":\"unacknowledged\"}\n"), 0o600)
	mounts := requireCollectorMounts(t, cfg)
	matched := false
	for _, mount := range mounts {
		if !strings.HasPrefix(mount.Host, store.Root+string(filepath.Separator)) {
			continue
		}
		rel, err := filepath.Rel(filepath.Join(store.area(), "logs"), mount.Host)
		if err != nil || !filepath.IsLocal(rel) || !mount.ReadOnly {
			t.Fatalf("collector can access non-record runtime data: %+v", mount)
		}
		if mount.Container == "/data/honeypots/ssh-proxy/logs/cells/ssh-backend-1" {
			matched = true
			if mount.Host != filepath.Dir(current) {
				t.Fatal("logical cell mount lost its trusted physical mapping")
			}
		}
	}
	if !matched {
		t.Fatal("collector does not retain logical cell identity")
	}
	sources := requireCollectorSources(t, cfg)
	generic, native := false, false
	for _, source := range sources {
		switch source.Name {
		case "ssh-proxy_logs":
			generic = true
			if source.HostDir != filepath.Join(store.area(), "logs") || source.Read("cells/opaque/current/e.json") {
				t.Fatal("broker source overlaps native records")
			}
		case SSHBackendLogSource:
			native = true
			if source.HostDir != filepath.Join(store.area(), "logs", "cells") || !source.Read(store.slot("ssh-backend-1")+"/current/uid-1001/events.json") {
				t.Fatal("native source lost external mapping")
			}
		}
	}
	if !generic || !native {
		t.Fatal("missing explicit collector source identities")
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.generateServiceConfigs(); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(cfg.DataPath, "collector", SSHBackendLogSource, "checkpoints.json")
	if _, err := os.Lstat(checkpoint); !os.IsNotExist(err) {
		t.Fatal("uncheckpointed native evidence was silently marked delivered")
	}
}

func TestSSHStoreMissingPriorLayoutCannotMoveExistingBindSources(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	source := filepath.Join(cfg.DataPath, "honeypots", sshBackendDataDir, "shared-hostkeys", "key")
	before := storageWrite(t, source, []byte("existing identity"), 0o600)
	if err := prepareSSHRuntimeLayout(context.Background(), cfg); err == nil {
		t.Fatal("missing stop proof permitted migration")
	}
	after, err := os.Stat(source)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("failed stop proof moved existing bind source")
	}
	if _, err := os.Lstat(filepath.Join(cfg.DataPath, sshStorePointer)); !os.IsNotExist(err) {
		t.Fatal("failed stop proof reserved persistent destination")
	}
}

func TestRemoveNeutralStoreRequiresSuccessfulStopAndKeepsCustomData(t *testing.T) {
	for _, scenario := range []string{"success", "stop-failure", "custom-data"} {
		t.Run(scenario, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			cfg := config.Default("remove-neutral")
			cfg.QPotID = "qp_removeneutralstable1234"
			normal := cfg.DataPath
			if scenario == "custom-data" {
				cfg.DataPath = t.TempDir()
			}
			cfg.ConfigPath = filepath.Join(normal, "config.yaml")
			if err := os.MkdirAll(normal, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(cfg.DataPath, 0o750); err != nil {
				t.Fatal(err)
			}
			enableOnly(cfg, sshProxyHoneypot)
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			prepareSSHStoreForTest(t, cfg)
			store, err := sshStoreAt(cfg.DataPath)
			if err != nil {
				t.Fatal(err)
			}
			record := organizationFakeDocker(t)
			storageWrite(t, cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, false), 0o600)
			key := filepath.Join(store.keys(false), "key")
			storageWrite(t, key, []byte("persist"), 0o600)
			if scenario == "stop-failure" {
				t.Setenv("SSH_TEST_EXIT", "19")
			}
			err = Remove(context.Background(), cfg.InstanceName)
			if scenario == "stop-failure" {
				if err == nil {
					t.Fatal("uncertain live stop authorized removal")
				}
				if data, _ := os.ReadFile(key); string(data) != "persist" {
					t.Fatal("failed stop deleted keys")
				}
				if _, err := os.Stat(normal); err != nil {
					t.Fatal("failed stop deleted instance")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				_, statErr := os.Stat(store.Root)
				if (statErr == nil) != (scenario == "custom-data") {
					t.Fatalf("wrong external root removal policy: %v", statErr)
				}
				if _, err := os.Stat(normal); !os.IsNotExist(err) {
					t.Fatal("normal instance directory remains")
				}
			}
			commands, _ := os.ReadFile(record)
			if scenario != "custom-data" && !strings.Contains(string(commands), "\ndown\n--remove-orphans\n") {
				t.Fatal("owned store removal lacked authoritative locked stop")
			}
		})
	}
}

func TestRemoveDefaultSymlinkCannotStopOrDeleteAnotherRuntimeStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture requires host privilege")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cfg := config.Default("victim")
	if err := os.MkdirAll(cfg.DataPath, 0o750); err != nil {
		t.Fatal(err)
	}
	prepareSSHStoreForTest(t, cfg)
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(store.keys(false), "key")
	before := storageWrite(t, key, []byte("other instance identity"), 0o600)
	// Omitted data_path makes the loader default to the lexical alias, while
	// the runtime marker correctly identifies the target's canonical directory.
	storageWrite(t, cfg.ConfigPath, []byte("instance_name: victim\n"), 0o600)
	alias := config.Default("alias").DataPath
	if err := os.Symlink(cfg.DataPath, alias); err != nil {
		t.Fatal(err)
	}
	commands := organizationFakeDocker(t)
	if err := Remove(context.Background(), "alias"); err == nil {
		t.Fatal("default-path alias authorized other instance removal")
	}
	if _, err := os.Lstat(commands); !os.IsNotExist(err) {
		t.Fatal("alias removal reached Docker before rejecting foreign path")
	}
	after, err := os.Stat(key)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("alias removal changed other instance identity")
	}
	if _, err := os.Lstat(alias); err != nil {
		t.Fatal("rejected removal changed alias")
	}
}

func TestSSHRuntimeMarkerStateOrderAndPrivateNamespace(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	prepareSSHStoreForTest(t, cfg)
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(store.Root) == store.Namespace || store.slot("ssh-backend-1") == proxy.ContextStorageName(filepath.Base(store.Root), "ssh-backend-1") {
		t.Fatal("public root ID reveals finite-service MAC key")
	}
	for _, state := range []string{"migrating", "invalid", ""} {
		owner := store
		owner.State = state
		if err := writeSSHStoreRecord(store.Root, sshStoreOwner, owner); err != nil {
			t.Fatal(err)
		}
		if _, err := sshStoreAt(cfg.DataPath); err == nil {
			t.Fatalf("ready pointer accepted owner state %q", state)
		}
	}
	for _, ownerState := range []string{"migrating", "ready"} {
		pending := store
		pending.State = "migrating"
		owner := store
		owner.State = ownerState
		if err := writeSSHStoreRecord(cfg.DataPath, sshStorePointer, pending); err != nil {
			t.Fatal(err)
		}
		if err := writeSSHStoreRecord(store.Root, sshStoreOwner, owner); err != nil {
			t.Fatal(err)
		}
		if _, err := sshStoreAt(cfg.DataPath); err != nil {
			t.Fatalf("legitimate owner-first transition rejected: %v", err)
		}
	}
	if err := writeSSHStoreRecord(store.Root, sshStoreOwner, store); err != nil {
		t.Fatal(err)
	}
	if err := writeSSHStoreRecord(cfg.DataPath, sshStorePointer, store); err != nil {
		t.Fatal(err)
	}
	// The namespace is a host secret: no service, the broker included, gets
	// it. Environment, generated files and visible mount sources use the
	// public root ID and opaque leaf IDs, never the MAC key itself.
	rendered := renderComposeCfg(t, cfg)
	var doc struct {
		Services map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatal(err)
	}
	for name, service := range doc.Services {
		data, err := yaml.Marshal(service)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), store.Namespace) {
			t.Fatalf("private namespace exposed in %s", name)
		}
	}
}

func TestSSHBrokerHostReadableOnlyForVerifiedReadyPrivateStore(t *testing.T) {
	cfg := unreservedSSHStoreConfig(t)
	if enabled, err := sshBrokerHostReadable(cfg); err != nil || enabled {
		t.Fatal("unreserved plan enabled readable broker metadata")
	}
	if strings.Contains(renderComposeCfg(t, cfg), "QPOT_SSHPROXY_HOST_READABLE_LOG=") {
		t.Fatal("dry planning opted a custom/legacy source into readable logs")
	}
	prepareSSHStoreForTest(t, cfg)
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	if enabled, err := sshBrokerHostReadable(cfg); err != nil || !enabled {
		t.Fatalf("private ready store not readable by host: %v", err)
	}
	var doc sshCellCompose
	if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &doc); err != nil {
		t.Fatal(err)
	}
	for name, service := range doc.Services {
		value, present := sshCellEnv(service.Environment)["QPOT_SSHPROXY_HOST_READABLE_LOG"]
		if present != (name == sshProxyHoneypot) || present && value != "1" {
			t.Fatalf("host-readable flag escaped trusted broker: %s %q", name, value)
		}
		if name == sshProxyHoneypot {
			expected := filepath.ToSlash(filepath.Join(store.area(), "logs", "broker")) + ":/var/log/ssh-proxy"
			found := false
			for _, mount := range service.Volumes {
				found = found || filepath.ToSlash(mount) == expected
			}
			if !found {
				t.Fatal("readable flag did not cover the actual broker bind source under private store")
			}
		}
	}
	pending := store
	pending.State = "migrating"
	if err := writeSSHStoreRecord(cfg.DataPath, sshStorePointer, pending); err != nil {
		t.Fatal(err)
	}
	if enabled, err := sshBrokerHostReadable(cfg); err != nil || enabled {
		t.Fatal("pending migration opted into readable logs")
	}
	if err := writeSSHStoreRecord(cfg.DataPath, sshStorePointer, store); err != nil {
		t.Fatal(err)
	}
	foreign := store
	foreign.Instance = "foreign"
	if err := writeSSHStoreRecord(store.Root, sshStoreOwner, foreign); err != nil {
		t.Fatal(err)
	}
	if enabled, err := sshBrokerHostReadable(cfg); err == nil || enabled {
		t.Fatal("invalid private store silently enabled readable metadata")
	}
}
