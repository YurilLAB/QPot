package instance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/sshbackend"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func organizationTestConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cfg := config.Default("organization-test")
	cfg.QPotID = "qp_organizationtest000000001"
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	for name, hp := range cfg.Honeypots {
		hp.Enabled = name == sshProxyHoneypot
		if hp.Enabled {
			hp.CustomConfig["environment"] = "organization"
			hp.CustomConfig["image_source"] = "local"
		}
		cfg.Honeypots[name] = hp
	}
	prepareSSHStoreForTest(t, cfg)
	return cfg
}

func organizationManifestFile(t *testing.T, m sshbackend.Manifest, name string) sshbackend.File {
	t.Helper()
	for _, file := range m.Files {
		if file.Path == name {
			return file
		}
	}
	t.Fatalf("missing scene file %s", name)
	return sshbackend.File{}
}

func TestSSHOrganizationSceneConsistency(t *testing.T) {
	cfg := organizationTestConfig(t)
	cells := requireSSHOrgCells(t, cfg)
	if len(cells) != 2 || !reflect.DeepEqual(cells, requireSSHOrgCells(t, cfg)) {
		t.Fatal("organization must have the configured stable cell count")
	}
	for i, cell := range cells {
		if cell.App != fmt.Sprintf("ssh-backend-%d", i+1) || cell.Network != sshBackendNetwork(cell.App) || !strings.Contains(cell.DBImage, "@sha256:") {
			t.Fatalf("unexpected cell wiring: %+v", cell)
		}
		app, err := sshbackend.DecodeManifest([]byte(cell.AppSceneJSON))
		if err != nil {
			t.Fatal(err)
		}
		backup, err := sshbackend.DecodeManifest([]byte(cell.BackupSceneJSON))
		if err != nil {
			t.Fatal(err)
		}
		if app.Database != backup.Database || app.Backup != backup.Backup || app.Database.Host != "db" || app.Backup.Host != "backup" || cell.BackupUsersCSV != app.Backup.User+":"+app.Backup.Password {
			t.Fatal("app and backup describe different services/accounts")
		}
		if app.Database.Password == cell.DBPassword || strings.Contains(cell.AppSceneJSON, cell.DBPassword) || strings.Contains(cell.BackupSceneJSON, cell.DBPassword) {
			t.Fatal("database administrator account must not be planted in either SSH host")
		}
		private := organizationManifestFile(t, app, "/srv/app/.ssh/id_ed25519")
		signer, err := ssh.ParsePrivateKey([]byte(private.Content))
		if err != nil || private.Mode != 0o600 {
			t.Fatalf("invalid client identity or mode: %v", err)
		}
		authorized := organizationManifestFile(t, backup, "/home/bkp/.ssh/authorized_keys")
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized.Content))
		if err != nil || !slices.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
			t.Fatalf("backup does not accept the application's actual key: %v", err)
		}
		known := organizationManifestFile(t, app, "/srv/app/.ssh/known_hosts")
		fields := strings.Fields(known.Content)
		if len(fields) != 3 || !strings.Contains(fields[0], "backup01.") {
			t.Fatal("missing complete backup host aliases")
		}
		for _, secret := range []string{app.Database.Password, app.Backup.Password} {
			if !sshSafeToken(secret) {
				t.Fatal("derived password does not fit the actual account/environment transport")
			}
		}
		if !slices.Contains(cell.AppAliases, cell.AppHostname) {
			t.Fatal("application hostname must resolve on its own cell")
		}
	}
	old := cells[0].AppSceneJSON
	cfg.QPotID = "qp_organizationtest000000002"
	if requireSSHOrgCells(t, cfg)[0].AppSceneJSON == old {
		t.Fatal("separate instance identities share a scene")
	}
}

func TestSSHOrganizationPreparationAndSQL(t *testing.T) {
	cfg := organizationTestConfig(t)
	if err := prepareSSHOrganization(cfg); err != nil {
		t.Fatal(err)
	}
	scene := newSSHOrganization(cfg)
	for _, cell := range requireSSHOrgCells(t, cfg) {
		data, err := os.ReadFile(cell.DBInitSQLPath)
		if err != nil || !strings.Contains(string(data), "SET ROLE app_service;") || !strings.Contains(string(data), scene.schemaSQL()) {
			t.Fatalf("SQL bootstrap does not contain its matching schema/data: %v", err)
		}
		app, _ := sshbackend.DecodeManifest([]byte(cell.AppSceneJSON))
		backup, _ := sshbackend.DecodeManifest([]byte(cell.BackupSceneJSON))
		initial := organizationManifestFile(t, backup, "/srv/backups/"+cell.DBName+"/initial.sql")
		if initial.Content != scene.schemaSQL() || strings.Contains(initial.Content, "PASSWORD") {
			t.Fatal("initial SQL backup must match data without the role/admin credentials")
		}
		key, err := os.ReadFile(filepath.Join(cell.BackupKeyDir, "ssh_host_ed25519_key"))
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		known := organizationManifestFile(t, app, "/srv/app/.ssh/known_hosts")
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(strings.Fields(known.Content)[1:], " ")))
		if err != nil || !slices.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
			t.Fatal("known_hosts does not match the real backup host identity")
		}
		if runtime.GOOS != "windows" {
			info, _ := os.Stat(cell.DBInitSQLPath)
			if info.Mode().Perm() != 0o644 {
				t.Fatal("nonroot PostgreSQL cannot read its initialization file")
			}
		}
	}
	if runtime.GOOS != "windows" {
		command := exec.Command("sh", "-n")
		command.Stdin = strings.NewReader(scene.backupScript())
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("actual backup script is not shell syntax: %v: %s", err, out)
		}
	}
}

func TestSSHOrganizationDisabledAndExplicitHostname(t *testing.T) {
	cfg := organizationTestConfig(t)
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Stealth.FakeHostname = "ops.example.internal"
	cfg.Honeypots[sshProxyHoneypot] = hp
	cell := requireSSHOrgCells(t, cfg)[0]
	if cell.AppHostname != hp.Stealth.FakeHostname || !slices.Contains(cell.AppAliases, hp.Stealth.FakeHostname) {
		t.Fatal("explicit application hostname was lost")
	}
	hp.Enabled = false
	cfg.Honeypots[sshProxyHoneypot] = hp
	if len(requireSSHOrgCells(t, cfg)) != 0 || len(allSSHCellServiceNames(cfg)) != 6 {
		t.Fatal("disabled render and stop-boundary must be distinct")
	}
	hp.CustomConfig["environment"] = "standalone"
	cfg.Honeypots[sshProxyHoneypot] = hp
	if len(allSSHCellServiceNames(cfg)) != 2 {
		t.Fatal("standalone must not create organization companions")
	}
}

func TestSSHOrganizationRejectsConflictingApplicationHostnames(t *testing.T) {
	cfg := organizationTestConfig(t)
	domain := newSSHOrganization(cfg).domain
	for _, hostname := range []string{"db", "DB", "db01", "db01." + domain, "backup", "Backup01", "backup01." + domain, sshProxyHoneypot, "ssh-backend-1-db", "ssh-backend-2-backup", "localhost", "localhost.localdomain"} {
		hp := cfg.Honeypots[sshProxyHoneypot]
		hp.Stealth.FakeHostname = hostname
		cfg.Honeypots[sshProxyHoneypot] = hp
		if err := validateSSHHostnames(cfg); err == nil {
			t.Fatalf("ambiguous application hostname %q was accepted", hostname)
		}
	}
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Stealth.FakeHostname = "ops01." + domain
	cfg.Honeypots[sshProxyHoneypot] = hp
	if err := validateSSHHostnames(cfg); err != nil {
		t.Fatalf("distinct application hostname was rejected: %v", err)
	}
}

func TestSSHHostnamesRejectPoolServiceNamesBeforeRendering(t *testing.T) {
	for _, mode := range []string{"standalone", "organization"} {
		t.Run(mode, func(t *testing.T) {
			cfg := organizationTestConfig(t)
			hp := cfg.Honeypots[sshProxyHoneypot]
			hp.CustomConfig["backends"] = "1" // also reserve IDs beyond the current pool
			hp.CustomConfig["environment"] = mode
			cfg.Honeypots[sshProxyHoneypot] = hp
			for slot := 1; slot <= maxSSHBackends; slot++ {
				service := fmt.Sprintf("ssh-backend-%d", slot)
				for _, hostname := range []string{service, "." + strings.ToUpper(service) + "-", service + "-db", service + "-backup"} {
					t.Run(hostname, func(t *testing.T) {
						hp := cfg.Honeypots[sshProxyHoneypot]
						hp.Stealth.FakeHostname = hostname
						cfg.Honeypots[sshProxyHoneypot] = hp
						if _, err := (&ComposeGenerator{Config: cfg, Sandbox: mustSandbox(t, cfg)}).Generate(); err == nil || !strings.Contains(err.Error(), "conflicts with an SSH pool service") {
							t.Fatalf("pool service hostname %q reached the rendered deployment: %v", hostname, err)
						}
					})
				}
			}
			for _, hostname := range []string{"app01", "ops01.example.internal", "ssh-backend-2.example.internal", "db01.example.internal", "ssh-backend-17", "ssh-backend-team"} {
				hp := cfg.Honeypots[sshProxyHoneypot]
				hp.Stealth.FakeHostname = hostname
				cfg.Honeypots[sshProxyHoneypot] = hp
				if _, err := (&ComposeGenerator{Config: cfg, Sandbox: mustSandbox(t, cfg)}).Generate(); err != nil {
					t.Fatalf("distinct application hostname %q was rejected: %v", hostname, err)
				}
			}
		})
	}
}

func organizationComposeFixture(t *testing.T, instanceName string, cells int, organization bool) []byte {
	t.Helper()
	services := map[string]any{}
	add := func(name, owner, honeypot string) {
		image := "fixture"
		if name == sshProxyHoneypot {
			image = "qpot-local/ssh-proxy:development"
		} else if sshCellApp(name) != "" && !strings.HasSuffix(name, "-db") {
			image = "qpot-local/ssh-backend:development"
		}
		services[name] = map[string]any{"image": image, "labels": map[string]string{"qpot.instance": owner, "qpot.honeypot": honeypot}}
	}
	add(sshProxyHoneypot, instanceName, sshProxyHoneypot)
	for n := 1; n <= cells; n++ {
		app := fmt.Sprintf("ssh-backend-%d", n)
		add(app, instanceName, "ssh-backend")
		if organization {
			add(app+"-db", instanceName, "ssh-backend")
			add(app+"-backup", instanceName, "ssh-backend")
		}
	}
	add("cowrie", instanceName, "cowrie")
	add("database", instanceName, "")
	add("ssh-backend-16", "other-instance", "ssh-backend")
	data, err := yaml.Marshal(map[string]any{"services": services})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func organizationFakeDocker(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable fixture")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "commands")
	code := `#!/bin/sh
printf 'CALL\n' >>"$SSH_TEST_COMMANDS"
printf '%s\n' "$@" >>"$SSH_TEST_COMMANDS"
case " $* " in
 *" info "*)
  if [ -n "${SSH_TEST_RESOURCE_FILE:-}" ]; then cat "$SSH_TEST_RESOURCE_FILE"; else
   printf '%s\n' '{"CgroupDriver":"systemd","MemoryLimit":true,"PidsLimit":true,"CPUCfsQuota":true}'
  fi
  exit "${SSH_TEST_RESOURCE_EXIT:-0}"
  ;;
 *" ps "*)
  if [ -n "${SSH_TEST_PS_FILE:-}" ] && [ -f "$SSH_TEST_COMMANDS.up" ]; then cat "$SSH_TEST_PS_FILE"; exit 0; fi
  state=running
  if [ -f "$SSH_TEST_COMMANDS.stopped" ]; then state=exited; fi
  printf '[{"Service":"ssh-proxy","State":"%s"}]\n' "$state"
  exit 0
  ;;
 *" stop "*|*" down "*)
  case " $* " in
   *" ssh-proxy "*|*" down "*)
    if [ "${SSH_TEST_EXIT:-0}" = 0 ]; then : > "$SSH_TEST_COMMANDS.stopped"; fi
    ;;
  esac
  ;;
 *" up "*)
  : > "$SSH_TEST_COMMANDS.up"
  case " $* " in
   *" ssh-proxy "*)
    if [ -n "${SSH_TEST_DEPLOY_STARTED:-}" ]; then
     : > "$SSH_TEST_DEPLOY_STARTED"
     while [ ! -f "$SSH_TEST_DEPLOY_RELEASE" ]; do sleep 0.01; done
    fi
    if [ "${SSH_TEST_EXIT:-0}" = 0 ]; then rm -f "$SSH_TEST_COMMANDS.stopped"; fi
    ;;
  esac
  ;;
 *" restart "*)
  if [ -n "${SSH_TEST_RESTART_STARTED:-}" ]; then
   : > "$SSH_TEST_RESTART_STARTED"
   while [ ! -f "$SSH_TEST_RESTART_RELEASE" ]; do sleep 0.01; done
  fi
  ;;
esac
exit "${SSH_TEST_EXIT:-0}"
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(code), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_TEST_COMMANDS", record)
	return record
}

func TestSSHOrganizationRetiresOnlyObsoleteOwnedCells(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.CustomConfig["environment"] = "standalone"
	hp.CustomConfig["backends"] = "1"
	cfg.Honeypots[sshProxyHoneypot] = hp
	old := organizationComposeFixture(t, cfg.InstanceName, 2, true)
	if err := retireSSHCells(context.Background(), cfg, old); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(record)
	text := string(data)
	for _, name := range []string{"ssh-backend-1", "ssh-backend-1-db", "ssh-backend-1-backup", "ssh-backend-2", "ssh-backend-2-db", "ssh-backend-2-backup"} {
		if !strings.Contains(text, "\n"+name+"\n") {
			t.Fatalf("prior cell member %s not retired", name)
		}
	}
	for _, name := range []string{"cowrie", "database", "ssh-backend-16", sshProxyHoneypot} {
		if strings.Contains(text, "\n"+name+"\n") {
			t.Fatalf("retirement selected unrelated service %s", name)
		}
	}
	if strings.Contains(text, "--remove-orphans") || !strings.Contains(text, "\nrm\n--stop\n--force\n") {
		t.Fatal("retirement must explicitly name only the owned old group")
	}
	left, _ := filepath.Glob(filepath.Join(cfg.DataPath, ".ssh-layout-*.yaml"))
	if len(left) != 0 {
		t.Fatal("private old-layout snapshot leaked after retirement")
	}
}

func TestSSHOrganizationAcceptsComposeLabelRepresentations(t *testing.T) {
	input := []byte("services:\n  ssh-backend-1:\n    labels: [qpot.instance=org, qpot.honeypot=ssh-backend]\n  unrelated:\n    labels: [other=value]\n")
	layout, err := parseSSHLayout(input, "org")
	if err != nil || !reflect.DeepEqual(layout.Groups["ssh-backend-1"], []string{"ssh-backend-1"}) {
		t.Fatalf("legal Compose label list was lost: %v", err)
	}
}

func TestSSHOrganizationResetWaitsForWholeGroupAndRejectsReplay(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	if err := os.WriteFile(cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600); err != nil {
		t.Fatal(err)
	}
	r := requireBackendRecycler(t, cfg)
	if err := os.MkdirAll(r.GenerationDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if err := bumpGeneration(r.GenerationDir, "ssh-backend-1"); err != nil {
			t.Fatal(err)
		}
	}
	generation := uint64(4)
	if err := r.resetCell(context.Background(), "ssh-backend-1", &generation); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(record)
	text := string(data)
	if !strings.Contains(text, "\n--wait\n--wait-timeout\n150\n") || strings.Contains(text, "ssh-backend-2") || !strings.Contains(text, "ssh-backend-1-backup\n") || !strings.Contains(text, "ssh-backend-1-db\n") || r.generation("ssh-backend-1") != 5 {
		t.Fatalf("not a whole healthy cell reset: %s", text)
	}
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if err := r.resetCell(context.Background(), "ssh-backend-1", &generation); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("old generation reset a fresh cell")
	}
	t.Setenv("SSH_TEST_EXIT", "19")
	generation = 5
	if err := r.resetCell(context.Background(), "ssh-backend-1", &generation); err == nil || r.generation("ssh-backend-1") != 5 {
		t.Fatal("partial/unhealthy group reset was marked reusable")
	}
}

func TestSSHOrganizationCandidateFailuresKeepPriorLayout(t *testing.T) {
	for _, scenario := range []string{"invalid environment", "conflicting application hostname", "conflicting ingress hostname", "conflicting standalone ingress hostname", "auxiliary write failure"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := organizationTestConfig(t)
			record := organizationFakeDocker(t)
			prior := organizationComposeFixture(t, cfg.InstanceName, 2, true)
			if err := os.WriteFile(cfg.GetDockerComposePath(), prior, 0o600); err != nil {
				t.Fatal(err)
			}
			hp := cfg.Honeypots[sshProxyHoneypot]
			hp.CustomConfig["backends"] = "1"
			hp.CustomConfig["environment"] = "standalone"
			if scenario == "invalid environment" {
				hp.CustomConfig["environment"] = "unrecognized-layout"
			} else if scenario == "conflicting application hostname" {
				hp.CustomConfig["environment"] = "organization"
				hp.Stealth.FakeHostname = "db01"
			} else if scenario == "conflicting ingress hostname" {
				hp.CustomConfig["environment"] = "organization"
				hp.Stealth.FakeHostname = "ssh-backend-2"
			} else if scenario == "conflicting standalone ingress hostname" {
				hp.Stealth.FakeHostname = "ssh-backend-2"
			} else if err := os.Mkdir(filepath.Join(cfg.DataPath, "vector.yaml"), 0o700); err != nil {
				t.Fatal(err)
			}
			cfg.Honeypots[sshProxyHoneypot] = hp
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Initialize(context.Background()); err == nil {
				t.Fatal("invalid candidate was reported as initialized")
			}
			actual, err := os.ReadFile(cfg.GetDockerComposePath())
			if err != nil || !slices.Equal(actual, prior) {
				t.Fatal("candidate failure overwrote the working Compose layout")
			}
			commands, _ := os.ReadFile(record)
			for _, mutation := range []string{"\nrm\n", "\nstop\n", "\nup\n"} {
				if strings.Contains(string(commands), mutation) {
					t.Fatalf("candidate failure changed live cells: %s", commands)
				}
			}
		})
	}
}

func TestSSHOrganizationStopUsesActualPriorCompanions(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	if err := os.WriteFile(cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600); err != nil {
		t.Fatal(err)
	}
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Enabled = false
	hp.CustomConfig["environment"] = "standalone"
	hp.CustomConfig["backends"] = "1"
	cfg.Honeypots[sshProxyHoneypot] = hp
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.StopHoneypot(context.Background(), sshProxyHoneypot); err != nil {
		t.Fatal(err)
	}
	commands, _ := os.ReadFile(record)
	for _, name := range []string{"ssh-backend-1-db", "ssh-backend-1-backup", "ssh-backend-2-db", "ssh-backend-2-backup"} {
		if !strings.Contains(string(commands), "\n"+name+"\n") {
			t.Fatalf("saved settings concealed deployed companion %s", name)
		}
	}
	if strings.Contains(string(commands), "\nssh-backend-16\n") {
		t.Fatal("stop selected a different instance's companion")
	}
	// The previous Compose layout remains on disk. A queued end-of-session
	// event must not use it to recreate cells after an explicit operator stop.
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	recycler := requireBackendRecycler(t, cfg)
	generation := uint64(0)
	if err := recycler.resetCell(context.Background(), "ssh-backend-1", &generation); err != nil {
		t.Fatal(err)
	}
	commands, _ = os.ReadFile(record)
	if strings.Contains(string(commands), "\nup\n") || recycler.generation("ssh-backend-1") != 0 {
		t.Fatal("pending session request restarted an explicitly stopped cell")
	}
}

func TestSSHOrganizationRecreateHoldsLockThroughDockerMutation(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	started, release := record+".started", record+".release"
	t.Setenv("SSH_TEST_DEPLOY_STARTED", started)
	t.Setenv("SSH_TEST_DEPLOY_RELEASE", release)
	defer os.WriteFile(release, nil, 0o600)
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- manager.RecreateHoneypot(ctx, sshProxyHoneypot) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("operator deployment did not enter Docker up")
		}
		time.Sleep(5 * time.Millisecond)
	}
	recycler := requireBackendRecycler(t, cfg)
	generation := uint64(0)
	resetCtx, resetCancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer resetCancel()
	if err := recycler.resetCell(resetCtx, "ssh-backend-1", &generation); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("recycler did not wait for operator deployment: %v", err)
	}
	commands, _ := os.ReadFile(record)
	if strings.Contains(string(commands), "\n--wait\n") || recycler.generation("ssh-backend-1") != 0 {
		t.Fatal("cell was reset/marked fresh while operator deployment was still in progress")
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := recycler.resetCell(context.Background(), "ssh-backend-1", &generation); err != nil || recycler.generation("ssh-backend-1") != 1 {
		t.Fatalf("recycler did not recover after deployment completed: %v", err)
	}
}

func TestSSHOrganizationFullStopRejectsPendingReset(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	if err := os.WriteFile(cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	recycler := requireBackendRecycler(t, cfg)
	generation := uint64(0)
	if err := recycler.resetCell(context.Background(), "ssh-backend-1", &generation); err != nil {
		t.Fatal(err)
	}
	commands, _ := os.ReadFile(record)
	if strings.Contains(string(commands), "\nup\n") || recycler.generation("ssh-backend-1") != 0 {
		t.Fatal("pending reset undid the operator's instance stop")
	}
}

func TestSSHOrganizationForegroundStartCreatesThenFollowsLogs(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// This test covers process/lifecycle ordering, not database connectivity.
	manager.dbOnce.Do(func() {})
	var states []map[string]string
	for _, service := range manager.expectedServices() {
		states = append(states, map[string]string{"Service": service, "State": "running", "Health": "healthy"})
	}
	data, err := json.Marshal(states)
	if err != nil {
		t.Fatal(err)
	}
	psPath := record + ".ps"
	if err := os.WriteFile(psPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_TEST_PS_FILE", psPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Start(ctx, false); err != nil {
		t.Fatal(err)
	}
	commands, _ := os.ReadFile(record)
	text := string(commands)
	up, logs := strings.Index(text, "\nup\n-d\n"), strings.Index(text, "\nlogs\n--follow\n--no-color\n")
	if strings.Count(text, "\nup\n") != 1 || up < 0 || logs <= up {
		t.Fatalf("foreground startup used another mutating up instead of following logs: %s", text)
	}
}

func TestSSHCellLifecycleLockCancellationAndRelease(t *testing.T) {
	dir := t.TempDir()
	first, err := lockSSHCells(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if second, err := lockSSHCells(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("concurrent lifecycle did not wait/cancel: %v", err)
	}
	first.Close()
	third, err := lockSSHCells(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	third.Close()
}

func TestSSHRecyclerPreservesNewStartupWhilePreviousResetFinishes(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sessions.json")
	write := func(g uint64) {
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		err = json.NewEncoder(file).Encode(map[string]any{"event_type": "ssh_proxy_backend_error", "backend": "ssh-backend-1", "generation": g})
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	write(0) // startup may precede the host monitor
	bumped := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	r := &BackendRecycler{LogPath: logPath, GenerationDir: dir, Services: map[string]bool{"ssh-backend-1": true}, Poll: 5 * time.Millisecond, RequireGeneration: true}
	r.Reset = func(ctx context.Context, service string, expected *uint64) error {
		if expected == nil {
			return errors.New("production request lost its zero generation")
		}
		if err := bumpGeneration(dir, service); err != nil {
			return err
		}
		if calls.Add(1) == 1 {
			close(bumped)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	select {
	case <-bumped:
	case <-time.After(2 * time.Second):
		t.Fatal("startup request emitted before monitor was lost")
	}
	write(1)
	time.Sleep(100 * time.Millisecond) // hold the worker busy across20 reader polls
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() != 2 || r.generation("ssh-backend-1") != 2 {
		t.Fatal("newer startup request was dropped while worker was busy")
	}
	write(0)
	write(1)
	time.Sleep(40 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatal("old replay reset an active fresh cell")
	}
}

func FuzzSSHOrganizationLayout(f *testing.F) {
	f.Add("services: {}")
	f.Add("services:\n  ssh-backend-1:\n    labels:\n      qpot.instance: org\n      qpot.honeypot: ssh-backend\n")
	f.Add("services:\n  ssh-backend-99:\n    labels:\n      qpot.instance: org\n      qpot.honeypot: ssh-backend\n")
	f.Add("services:\n  ssh-backend-1-db:\n    labels:\n      qpot.instance: other\n      qpot.honeypot: ssh-backend\n")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		layout, err := parseSSHLayout([]byte(input), "org")
		if err != nil {
			return
		}
		if len(layout.Groups) > maxSSHBackends {
			t.Fatal("rendered layout exceeded the finite cell pool")
		}
		for app, members := range layout.Groups {
			if sshCellApp(app) != app || len(members) > 3 {
				t.Fatal("rendered layout selected an unknown/oversized cell")
			}
			for _, member := range members {
				if sshCellApp(member) != app || strings.ContainsAny(member, "\r\n /\\") {
					t.Fatal("rendered layout escaped its fixed cell service names")
				}
			}
		}
	})
}

func TestSSHRecyclerRejectsFutureGenerationsAndFollowsRotatedLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sessions.json")
	line := func(g uint64) string {
		return fmt.Sprintf("{\"event_type\":\"ssh_proxy_backend_error\",\"backend\":\"ssh-backend-1\",\"generation\":%d}\n", g)
	}
	if err := os.WriteFile(logPath, []byte(line(99)+line(0)), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	r := &BackendRecycler{LogPath: logPath, GenerationDir: dir, Services: map[string]bool{"ssh-backend-1": true}, Poll: 5 * time.Millisecond, RequireGeneration: true}
	r.Reset = func(ctx context.Context, service string, expected *uint64) error {
		if expected == nil || *expected != r.generation(service) {
			return errors.New("untrusted generation reached reset")
		}
		if err := bumpGeneration(dir, service); err != nil {
			return err
		}
		calls.Add(1)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	wait := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for calls.Load() < want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if calls.Load() != want {
			t.Fatalf("got %d resets, want %d", calls.Load(), want)
		}
		time.Sleep(25 * time.Millisecond)
	}
	wait(1)
	if r.generation("ssh-backend-1") != 1 {
		t.Fatal("a future historical tag changed the authority")
	}
	// A restored/lost authority must not let an old future tag reset an active
	// cell. A restarted broker captures the actual new baseline and recovers.
	if err := os.WriteFile(filepath.Join(dir, "ssh-backend-1"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(line(1))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if calls.Load() != 1 || r.generation("ssh-backend-1") != 0 {
		t.Fatal("old future tag was replayed after authority rollback")
	}
	f, err = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(line(0))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	wait(2)
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	// The replacement is larger than the old file. Size-only rotation checks
	// would seek past its one-shot startup request and leave the slot stuck.
	if err := os.WriteFile(logPath, []byte(line(1)+strings.Repeat("not json\n", 300)), 0o600); err != nil {
		t.Fatal(err)
	}
	wait(3)
	if r.generation("ssh-backend-1") != 2 {
		t.Fatal("rotated-log startup request did not recover the whole cell")
	}
}
