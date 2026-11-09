package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/proxy"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// This explicitly gated test uses production-generated Compose, mandatory host
// guard, the real broker and host recycler. A host unable to apply the guard
// fails the test; it never substitutes a permissive network or fake service.
func TestSSHOrganizationLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_HIFI_LIVE") != "1" {
		t.Skip("set QPOT_TEST_HIFI_LIVE=1 on an isolated Docker host with NET_ADMIN and the locally built HiFi images")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("real HiFi cell integration requires a Linux Docker host")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	// Software-emulated validation hosts exercise the same real services and
	// controls. Keep the complete case bounded while allowing their slower I/O.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	cfg := config.Default(fmt.Sprintf("hifi-live-%d", time.Now().UnixNano()))
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	cfg.QPotID = "qp_hifilive0000000000000001"
	cfg.Security.SandboxMode = "none"
	cfg.WebUI.Enabled = false
	enableOnly(cfg, sshProxyHoneypot)
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.CustomConfig = map[string]string{"backends": "2", "environment": "organization", "image_source": "local"}
	hp.Stealth.CredentialTemplate = "abandoned-vps" // explicit root account for genuine state mutations
	cfg.Honeypots[sshProxyHoneypot] = hp
	runDocker := func(runCtx context.Context, args ...string) ([]byte, error) {
		command := exec.CommandContext(runCtx, "docker", args...)
		command.Dir = cfg.DataPath
		return command.CombinedOutput()
	}
	for _, image := range []string{sshProxyImage(cfg), sshBackendImage(cfg)} {
		if output, err := runDocker(ctx, "image", "inspect", image); err != nil {
			t.Fatalf("required test image %s unavailable; build local HiFi images and pull the pinned PostgreSQL image first: %v\n%s", image, err, output)
		}
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	compose := func(runCtx context.Context, args ...string) ([]byte, error) {
		return runDocker(runCtx, append([]string{"compose", "-f", cfg.GetDockerComposePath()}, args...)...)
	}
	var clients []*ssh.Client
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	t.Cleanup(func() {
		for _, client := range clients {
			_ = client.Close()
		}
		stopMonitor()
		<-monitorDone
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cleanupCancel()
		if output, err := compose(cleanupCtx, "logs", "--no-color", "--tail", "30", "netguard", sshProxyHoneypot); err != nil || t.Failed() {
			t.Logf("owned integration service logs (%v):\n%s", err, output)
		}
		if err := manager.Stop(cleanupCtx); err != nil {
			t.Errorf("remove owned integration services/networks: %v", err)
		}
		// Guards intentionally survive process exit. Remove only this test's
		// generated table after every owned guest has stopped.
		if output, err := compose(cleanupCtx, "run", "--rm", "--no-deps", "netguard", "remove"); err != nil {
			t.Logf("owned guard table cleanup (%v): %s", err, output)
		}
		// Recorded UID directories may be private to container users. The
		// disposable helper sees only this test's log folder and no network.
		logRoot, pathErr := sshStoreRecordRoot(cfg)
		if pathErr != nil {
			t.Errorf("owned log cleanup path: %v", pathErr)
			return
		}
		if output, err := runDocker(cleanupCtx, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m", "--user", "0:0", "--mount", "type=bind,source="+logRoot+",target=/c", "--entrypoint", "/bin/rm", sshBackendImage(cfg), "-rf", "--", "/c/cells"); err != nil {
			t.Logf("owned recording cleanup (%v): %s", err, output)
		}
	})
	recycler := requireBackendRecycler(t, cfg)
	go func() { defer close(monitorDone); recycler.Run(monitorCtx) }()
	// Fail immediately on a host that cannot enforce the actual generated
	// policy. This is a real Apply using the unchanged production guard image.
	if output, err := compose(ctx, "run", "--rm", "--no-deps", "netguard", "apply"); err != nil {
		t.Fatalf("mandatory generated HiFi guard could not be applied; this host cannot validate the complete topology (no bypass): %v\n%s", err, output)
	}
	if output, err := runDocker(ctx, "image", "inspect", sshOrganizationDBImage); err != nil {
		t.Fatalf("pull the pinned PostgreSQL image before running the full organization topology: %v\n%s", err, output)
	}
	lock, err := lockSSHCells(ctx, cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	services := append([]string{"netguard", sshProxyHoneypot}, allSSHCellServiceNames(cfg)...)
	output, upErr := compose(ctx, append([]string{"up", "-d", "--wait", "--wait-timeout", "150"}, services...)...)
	_ = lock.Close()
	if upErr != nil {
		t.Fatalf("start production-generated HiFi cell services: %v\n%s", upErr, output)
	}
	for _, app := range sshBackendServiceNames(cfg) {
		sshLiveResetWait(t, ctx, "initial trusted reset for "+app, func() bool { return recycler.generation(app) > 0 })
	}
	sharedKeys, err := sshStoreSharedKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(filepath.Join(sharedKeys, "ssh_host_ed25519_key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	password := ""
	for _, pair := range strings.Split(sshBackendUsersCSV(cfg), ",") {
		if user, value, _ := strings.Cut(pair, ":"); user == "root" {
			password = value
		}
	}
	if password == "" {
		t.Fatal("generated SSH account persona has no root credential")
	}
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(PublishedHostPorts(cfg)[portKey(sshProxyHoneypot, 2222)]))
	connect := func() *ssh.Client {
		var connected *ssh.Client
		sshLiveWait(t, ctx, "fresh broker lease", func() bool {
			configuration := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password(password)}, Timeout: 3 * time.Second,
				HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: func(_ string, remote net.Addr, actual ssh.PublicKey) error {
					host, _, err := net.SplitHostPort(remote.String())
					if err != nil || !net.ParseIP(host).IsLoopback() || !bytes.Equal(key.Marshal(), actual.Marshal()) {
						return fmt.Errorf("unexpected local test SSH identity")
					}
					return nil
				}}
			connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
			if err != nil {
				return false
			}
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			transport, channels, requests, err := ssh.NewClientConn(connection, address, configuration)
			if err != nil {
				_ = connection.Close()
				return false
			}
			if deadline, ok := ctx.Deadline(); ok {
				_ = connection.SetDeadline(deadline)
			}
			connected = ssh.NewClient(transport, channels, requests)
			return true
		})
		clients = append(clients, connected)
		return connected
	}
	command := func(client *ssh.Client, text string) string {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		output, err := session.CombinedOutput(text)
		if err != nil {
			t.Fatalf("real SSH command failed: %s\n%v\n%s", text, err, output)
		}
		return string(output)
	}
	lease := func(client *ssh.Client) (string, uint64) {
		var connection proxy.ConnectionContext
		if err := json.Unmarshal([]byte(command(client, "cat /run/audit-context/connection.json")), &connection); err != nil || connection.Generation == nil {
			t.Fatalf("missing trusted connection context: %v", err)
		}
		for _, app := range sshBackendServiceNames(cfg) {
			contextDir, err := sshStoreContext(cfg, app)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(filepath.Join(contextDir, "connection.json"))
			var host proxy.ConnectionContext
			if json.Unmarshal(data, &host) == nil && host.SessionID == connection.SessionID {
				return app, *connection.Generation
			}
		}
		t.Fatal("guest connection did not match any host-owned lease")
		return "", 0
	}
	first, second := connect(), connect()
	firstApp, firstGeneration := lease(first)
	secondApp, secondGeneration := lease(second)
	if firstApp == secondApp {
		t.Fatal("two concurrent ingress connections share one cell")
	}
	query := `. /srv/app/.env; PGPASSWORD="$DB_PASSWORD" psql -X -v ON_ERROR_STOP=1 -At -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c `
	command(first, `set -eu; printf 'first-private-transcript\n'; printf first > /srv/app/visitor-marker; chmod 640 /srv/app/visitor-marker; useradd -m validation-user; apt-get --no-download install -y tree; `+query+shellQuote("INSERT INTO assets VALUES (991, 'validation-host', 'probe', 'active');")+`; /usr/local/bin/backup-db`)
	backupCheck := `. /srv/app/.env; ssh -i /srv/app/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=/srv/app/.ssh/known_hosts "$BACKUP_USER@$BACKUP_HOST" `
	command(first, backupCheck+shellQuote(`set -eu; for file in /srv/backups/*/*.sql.gz; do gzip -t "$file"; gzip -cd "$file" | grep -q validation-host; done; printf 'first-private-transcript\n'`))
	if output := command(first, `set -eu; test "$(cat /srv/app/visitor-marker)" = first; test "$(stat -c %a /srv/app/visitor-marker)" = 640; id validation-user; dpkg-query -W tree; `+query+`'SELECT count(*) FROM assets WHERE id=991;'`); !strings.Contains(output, "1\n") {
		t.Fatal("real SQL state was not visible in a later SSH channel")
	}
	if output := command(second, `set -eu; test ! -e /srv/app/visitor-marker; printf second > /srv/app/second-marker; `+query+`'SELECT count(*) FROM assets WHERE id=991;'`); strings.TrimSpace(output) != "0" {
		t.Fatal("independent cell saw the other visitor's SQL state")
	}
	// Probe the real generated Docker bridges while both cells are leased.
	// Every address comes from these owned services; no external target is used.
	type endpoint struct {
		IPAddress string
		Gateway   string
	}
	type inspection struct {
		ID         string
		State      struct{ Pid int }
		HostConfig struct {
			NanoCpus  int64
			Memory    int64
			PidsLimit *int64
		}
		NetworkSettings struct{ Networks map[string]endpoint }
	}
	limits := cfg.GetEffectiveResourceLimits(sshProxyHoneypot)
	verifyKernelLimits := func(service string, item inspection) {
		t.Helper()
		declared := item.HostConfig
		wantedNano := limits.MaxCPUPercent / 100 * 1e9
		if declared.NanoCpus <= 0 || math.Abs(float64(declared.NanoCpus)-wantedNano) > max(1, wantedNano*2e-7) || declared.Memory != limits.MaxMemoryMB<<20 || declared.PidsLimit == nil || *declared.PidsLimit != limits.MaxPids {
			t.Fatalf("%s Docker resource declaration disagrees with effective configuration: %+v", service, declared)
		}
		if item.State.Pid <= 0 || len(item.ID) != 64 || strings.Trim(item.ID, "0123456789abcdef") != "" {
			t.Fatalf("%s has no stable owned process identity", service)
		}
		membership, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", item.State.Pid))
		if err != nil {
			t.Fatalf("read owned %s cgroup membership: %v", service, err)
		}
		groups := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(membership)), "\n") {
			fields := strings.SplitN(line, ":", 3)
			if len(fields) != 3 {
				t.Fatalf("invalid cgroup membership for owned %s", service)
			}
			relative := strings.TrimPrefix(fields[2], "/")
			if !filepath.IsLocal(relative) || !strings.Contains(relative, item.ID) {
				continue
			}
			for _, controller := range strings.Split(fields[1], ",") {
				groups[controller] = relative
			}
		}
		read := func(path string) string {
			t.Helper()
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read owned %s kernel limit %s: %v", service, path, err)
			}
			return strings.TrimSpace(string(data))
		}
		var CPU, memory, PIDs string
		if group, ok := groups[""]; ok {
			base := filepath.Join("/sys/fs/cgroup", group)
			CPU, memory, PIDs = read(filepath.Join(base, "cpu.max")), read(filepath.Join(base, "memory.max")), read(filepath.Join(base, "pids.max"))
		} else {
			for _, controller := range []string{"cpu", "memory", "pids"} {
				if groups[controller] == "" {
					t.Fatalf("%s lacks an owned %s cgroup", service, controller)
				}
			}
			cpuBase := filepath.Join("/sys/fs/cgroup/cpu", groups["cpu"])
			if _, err := os.Stat(cpuBase); err != nil {
				cpuBase = filepath.Join("/sys/fs/cgroup/cpu,cpuacct", groups["cpu"])
			}
			CPU = read(filepath.Join(cpuBase, "cpu.cfs_quota_us")) + " " + read(filepath.Join(cpuBase, "cpu.cfs_period_us"))
			memory = read(filepath.Join("/sys/fs/cgroup/memory", groups["memory"], "memory.limit_in_bytes"))
			PIDs = read(filepath.Join("/sys/fs/cgroup/pids", groups["pids"], "pids.max"))
		}
		parse := func(value string) int64 {
			t.Helper()
			result, err := strconv.ParseInt(value, 10, 64)
			if err != nil || result <= 0 {
				t.Fatalf("%s has a missing, unlimited or invalid kernel resource limit %q", service, value)
			}
			return result
		}
		parts := strings.Fields(CPU)
		if len(parts) != 2 {
			t.Fatalf("invalid CPU limit for owned %s: %q", service, CPU)
		}
		quota, period := parse(parts[0]), parse(parts[1])
		if period != 100000 || declared.NanoCpus > math.MaxInt64/period || quota != declared.NanoCpus*period/1e9 || parse(memory) != declared.Memory || parse(PIDs) != *declared.PidsLimit {
			t.Fatalf("%s kernel limits disagree with configured Docker limits: CPU=%q memory=%q PIDs=%q", service, CPU, memory, PIDs)
		}
		t.Logf("%s actual kernel limits: CPU=%s memory=%s PIDs=%s", service, CPU, memory, PIDs)
	}
	inspectService := func(service string) inspection {
		t.Helper()
		ids, err := compose(ctx, "ps", "-q", service)
		if err != nil || len(strings.Fields(string(ids))) != 1 {
			t.Fatalf("owned service %s container: %v %s", service, err, ids)
		}
		data, err := runDocker(ctx, "inspect", strings.TrimSpace(string(ids)))
		var inspected []inspection
		if err != nil || json.Unmarshal(data, &inspected) != nil || len(inspected) != 1 {
			t.Fatalf("inspect owned service %s: %v %s", service, err, data)
		}
		verifyKernelLimits(service, inspected[0])
		return inspected[0]
	}
	serviceEndpoint := func(service string) endpoint {
		t.Helper()
		inspected := inspectService(service)
		if len(inspected.NetworkSettings.Networks) != 1 {
			t.Fatalf("owned service %s has an ambiguous network endpoint", service)
		}
		for _, peer := range inspected.NetworkSettings.Networks {
			if ip := net.ParseIP(peer.IPAddress); ip == nil || ip.To4() == nil || !ip.IsPrivate() {
				t.Fatalf("owned service %s has an invalid private IPv4 address", service)
			}
			return peer
		}
		t.Fatal("owned service has no endpoint")
		return endpoint{}
	}
	inspectService(sshProxyHoneypot)
	inspectService(secondApp)
	appEndpoint := serviceEndpoint(firstApp)
	if gateway := net.ParseIP(appEndpoint.Gateway); gateway == nil || gateway.To4() == nil || !gateway.IsPrivate() {
		t.Fatal("owned app has no private bridge gateway")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(appEndpoint.Gateway, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var accepted atomic.Int64
	const hostMarker = "owned-host-control\n"
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(connection, hostMarker)
			_ = connection.Close()
		}
	}()
	control, err := net.DialTimeout("tcp4", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
	marker, readErr := io.ReadAll(control)
	_ = control.Close()
	if readErr != nil || string(marker) != hostMarker || accepted.Load() != 1 {
		t.Fatalf("owned host listener positive control failed: %v %q", readErr, marker)
	}
	tcpProbe := func(ip string, port int) string {
		return "timeout 3 /bin/bash -c " + shellQuote(fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", ip, port))
	}
	for _, peer := range []struct {
		suffix string
		port   int
	}{{"-db", 5432}, {"-backup", 22}} {
		own, other := serviceEndpoint(firstApp+peer.suffix), serviceEndpoint(secondApp+peer.suffix)
		command(first, tcpProbe(own.IPAddress, peer.port))
		command(second, tcpProbe(other.IPAddress, peer.port))
		command(first, "if "+tcpProbe(other.IPAddress, peer.port)+"; then printf 'unexpected cross-cell connection\\n' >&2; exit 1; fi")
	}
	command(first, "if "+tcpProbe(appEndpoint.Gateway, listener.Addr().(*net.TCPAddr).Port)+"; then printf 'unexpected host connection\\n' >&2; exit 1; fi")
	if accepted.Load() != 1 {
		t.Fatal("private cell reached the owned host listener")
	}
	t.Log("real Docker bridge probes: own-cell database and backup reachable; host and cross-cell database/backup denied")
	_ = first.Close()
	sshLiveResetWait(t, ctx, "whole first cell reset", func() bool { return recycler.generation(firstApp) > firstGeneration })
	if recycler.generation(secondApp) != secondGeneration || strings.TrimSpace(command(second, "cat /srv/app/second-marker")) != "second" {
		t.Fatal("resetting one cell disrupted another live visitor")
	}
	fresh := connect() // second cell remains leased, so only the first is free
	if app, _ := lease(fresh); app != firstApp {
		t.Fatal("fresh visitor did not receive the reset cell")
	}
	// The needle is assembled at runtime so this inspection command itself
	// cannot plant the previous visitor's literal marker into the new log.
	if output := command(fresh, `set -eu; test ! -e /srv/app/visitor-marker; ! getent passwd validation-user; ! dpkg-query -W -f='${Status}' tree 2>/dev/null | grep -q 'install ok installed'; needle="$(printf 'first-private-\164ranscript')"; ! grep -R -l -- "$needle" /var/log/ssh-backend; `+query+`'SELECT count(*) FROM assets WHERE id=991;'`); strings.TrimSpace(output) != "0" {
		t.Fatal("fresh cell retained previous visitor SQL data")
	}
	command(fresh, backupCheck+shellQuote(`set -eu; test -f /srv/backups/*/initial.sql; test -z "$(find /srv/backups -name '*.sql.gz' -print)"; needle="$(printf 'first-private-\164ranscript')"; ! grep -R -l -- "$needle" /var/log/ssh-backend`))
	for _, service := range sshCellServiceNames(cfg, firstApp) {
		archives, _ := filepath.Glob(filepath.Join(filepath.Dir(requireSSHLogDir(t, cfg, service)), fmt.Sprintf("archive-g%d-*", firstGeneration), "logs"))
		if len(archives) == 0 {
			t.Fatalf("closed %s logs were not retained outside new guests", service)
		}
	}
}

// A whole-cell reset has a three-minute production recreation deadline plus
// stopping and archiving. Observe that real operation without cancelling it at
// the shorter connection/readiness budget, while retaining the case deadline.
func sshLiveResetWait(t *testing.T, ctx context.Context, description string, condition func() bool) {
	t.Helper()
	sshLiveWaitWithin(t, ctx, description, 4*time.Minute, condition)
}

func sshLiveWait(t *testing.T, ctx context.Context, description string, condition func() bool) {
	t.Helper()
	sshLiveWaitWithin(t, ctx, description, 90*time.Second, condition)
}

func sshLiveWaitWithin(t *testing.T, ctx context.Context, description string, budget time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(budget)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", description, ctx.Err())
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		case <-tick.C:
		}
	}
}

// TestSSHOrganizationServicesLive exercises the real app -> database -> SSH
// backup workflow when host-network guard capability is unavailable. All three
// containers share ONE network-none namespace, with only loopback and no host
// ports. The app SSH port is adapted to2200 to avoid the backup's real port22.
// This proves component interoperability, not production cell isolation/reset.
func TestSSHOrganizationServicesLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_HIFI_SERVICES") != "1" {
		t.Skip("set QPOT_TEST_HIFI_SERVICES=1 for isolated connected service components")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("isolated connected service components require Linux Docker")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg := config.Default(fmt.Sprintf("hifi-services-%d", time.Now().UnixNano()))
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	cfg.QPotID = "qp_hifiservices0000000000001"
	cfg.Security.SandboxMode = "none"
	cfg.WebUI.Enabled = false
	enableOnly(cfg, sshProxyHoneypot)
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.CustomConfig = map[string]string{"backends": "1", "environment": "organization", "image_source": "local"}
	hp.Stealth.CredentialTemplate = "abandoned-vps"
	cfg.Honeypots[sshProxyHoneypot] = hp
	run := func(args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	}
	for _, image := range []string{sshBackendImage(cfg), sshOrganizationDBImage} {
		if output, err := run("image", "inspect", image); err != nil {
			t.Fatalf("required local component image missing:%v\n%s", err, output)
		}
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	cell := requireSSHOrgCells(t, cfg)[0]
	type service struct {
		Image, User, Hostname               string
		ReadOnly                            bool `yaml:"read_only"`
		Entrypoint, Command, Volumes, Tmpfs []string
		CapDrop                             []string `yaml:"cap_drop"`
		CapAdd                              []string `yaml:"cap_add"`
		SecurityOpt                         []string `yaml:"security_opt"`
		Environment                         any
	}
	var rendered struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &rendered); err != nil {
		t.Fatal(err)
	}
	specs := map[string]service{}
	for _, name := range sshCellServiceNames(cfg, cell.App) {
		var spec service
		node := rendered.Services[name]
		if err := node.Decode(&spec); err != nil {
			t.Fatal(err)
		}
		specs[name] = spec
	}
	rawConfig, err := os.ReadFile(filepath.Join("..", "..", "docker", "ssh-backend", "files", "sshd_config"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rawConfig, []byte("Port 22\n")) {
		t.Fatal("component app port adapter no longer matches the production SSH configuration")
	}
	var lines []string
	for _, line := range strings.Split(string(rawConfig), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines = append(lines, line)
		}
	}
	appConfig := filepath.Join(cfg.DataPath, "component-sshd.conf")
	if err := os.WriteFile(appConfig, []byte(strings.Replace(strings.Join(lines, "\n"), "Port 22\n", "Port 2200\n", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(appConfig, 0644); err != nil {
		t.Fatal(err)
	}
	mappedOwner := collectorMappedOwner(t, sshBackendImage(cfg))
	var started []string
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 60*time.Second)
		defer done()
		for i := len(started) - 1; i >= 0; i-- {
			if t.Failed() {
				output, _ := exec.CommandContext(cleanupCtx, "docker", "logs", "--tail", "25", started[i]).CombinedOutput()
				t.Logf("owned service%s:%s", started[i], output)
			}
			_, _ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", "-v", started[i]).CombinedOutput()
		}
		// Only this test's synthetic data is mounted; private capture modes stay intact.
		area, pathErr := SSHRuntimeLogArea(cfg)
		if pathErr != nil {
			t.Errorf("owned record cleanup path: %v", pathErr)
			return
		}
		for _, directory := range []string{cfg.DataPath, area} {
			args := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--user", "0:0", "--mount", "type=bind,src=" + directory + ",dst=/target", "--entrypoint", "/usr/bin/chown", sshBackendImage(cfg), "-R", "--no-dereference", mappedOwner, "/target"}
			if output, err := exec.CommandContext(cleanupCtx, "docker", args...).CombinedOutput(); err != nil {
				t.Errorf("restore only owned fixture data ownership:%v %s", err, output)
			}
		}
	})
	appName := cfg.InstanceName + "-app"
	backupName := cfg.InstanceName + "-backup"
	dbName := cfg.InstanceName + "-db"
	start := func(serviceID, name, network string, anchor bool) {
		t.Helper()
		spec := specs[serviceID]
		args := []string{"run", "-d", "--name", name, "--label", "qpot.validation=hifi-services", "--network", network, "--memory", "256m", "--cpus", "0.5", "--pids-limit", "128"}
		if anchor {
			args = append(args, "--hostname", spec.Hostname)
			for _, alias := range append(append(append([]string{}, cell.AppAliases...), cell.DBAliases...), cell.BackupAliases...) {
				args = append(args, "--add-host", alias+":127.0.0.1")
			}
		}
		if spec.ReadOnly {
			args = append(args, "--read-only")
		}
		if spec.User != "" {
			args = append(args, "--user", spec.User)
		}
		for _, cap := range spec.CapDrop {
			args = append(args, "--cap-drop", cap)
		}
		for _, cap := range spec.CapAdd {
			args = append(args, "--cap-add", cap)
		}
		for _, option := range spec.SecurityOpt {
			args = append(args, "--security-opt", option)
		}
		for _, mount := range spec.Volumes {
			args = append(args, "--volume", mount)
		}
		for _, tmp := range spec.Tmpfs {
			args = append(args, "--tmpfs", tmp)
		}
		for key, value := range sshCellEnv(spec.Environment) {
			// yamlInterpolatedStr doubles dollars for Compose. This component
			// calls Docker directly, so restore exactly that one escape layer.
			value = strings.ReplaceAll(value, "$$", "$")
			if key == "BACKEND_SCENE" {
				expected := cell.AppSceneJSON
				if serviceID == cell.Backup {
					expected = cell.BackupSceneJSON
				}
				if value != expected {
					t.Fatal("component scene differs from the production manifest")
				}
			}
			args = append(args, "--env", key+"="+value)
		}
		if anchor {
			args = append(args, "--mount", "type=bind,src="+appConfig+",dst=/etc/ssh/sshd_config,readonly")
		}
		if len(spec.Entrypoint) > 0 {
			args = append(args, "--entrypoint", spec.Entrypoint[0])
		}
		args = append(args, spec.Image)
		if len(spec.Entrypoint) > 1 {
			args = append(args, spec.Entrypoint[1:]...)
		}
		args = append(args, spec.Command...)
		started = append(started, name)
		if output, err := run(args...); err != nil {
			t.Fatalf("start owned network-none component%s:%v\n%s", name, err, output)
		}
	}
	start(cell.App, appName, "none", true)
	anchorID, err := run("inspect", "--format", "{{.Id}}", appName)
	if err != nil {
		t.Fatal(err)
	}
	start(cell.Database, dbName, "container:"+appName, false)
	start(cell.Backup, backupName, "container:"+appName, false)
	for _, name := range started {
		output, err := run("inspect", name)
		if err != nil {
			t.Fatal(err)
		}
		var info []struct {
			HostConfig struct {
				NetworkMode  string
				PortBindings map[string]any
			}
		}
		if json.Unmarshal(output, &info) != nil || len(info) != 1 || len(info[0].HostConfig.PortBindings) != 0 {
			t.Fatal("component unexpectedly publishes a host port")
		}
		want := "container:" + strings.TrimSpace(string(anchorID))
		if name == appName {
			want = "none"
		}
		if info[0].HostConfig.NetworkMode != want {
			t.Fatalf("component namespace differs:%s", info[0].HostConfig.NetworkMode)
		}
	}
	if output, err := run("exec", appName, "cat", "/proc/net/route"); err != nil || len(strings.Fields(string(output))) != 11 {
		t.Fatalf("component namespace has a non-loopback route:%v %s", err, output)
	}
	sshLiveWait(t, ctx, "component app SSH", func() bool {
		output, err := run("exec", appName, "/bin/bash", "-c", `exec 3<>/dev/tcp/127.0.0.1/2200; IFS= read -r line <&3; printf '%s' "$line"`)
		return err == nil && bytes.HasPrefix(output, []byte("SSH-2.0-OpenSSH"))
	})
	sshLiveWait(t, ctx, "component database", func() bool {
		_, err := run("exec", dbName, "pg_isready", "-h", "127.0.0.1", "-U", cell.DBUsername, "-d", cell.DBName)
		return err == nil
	})
	sshLiveWait(t, ctx, "component backup SSH", func() bool {
		_, err := run("exec", backupName, "/usr/local/libexec/session-audit", "health")
		return err == nil
	})
	// Self-login uses the real planted key with an explicitly pinned app host key.
	// Docker exec bootstraps only this test's authorized-key/known-host fixture.
	bootstrap := `set -eu; mkdir -p /root/.ssh; chmod 700 /root/.ssh; cp /srv/app/.ssh/id_ed25519.pub /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; printf '[127.0.0.1]:2200 %s\n' "$(cut -d' ' -f1-2 /run/sshd/bootstrap/keys/ssh_host_ed25519_key.pub)" > /tmp/component-known-hosts`
	if output, err := run("exec", appName, "/bin/bash", "-c", bootstrap); err != nil {
		t.Fatalf("owned SSH component setup:%v %s", err, output)
	}
	remote := func(command string, want int) string {
		t.Helper()
		args := []string{"exec", appName, "ssh", "-i", "/srv/app/.ssh/id_ed25519", "-p", "2200", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/tmp/component-known-hosts", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=3", "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2", "root@127.0.0.1", command}
		output, err := run(args...)
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("component SSH failed:%v", err)
			}
			code = exit.ExitCode()
		}
		if code != want {
			t.Fatalf("actual component SSH exit%d want%d:%s\n%s", code, want, command, output)
		}
		return string(output)
	}
	query := `. /srv/app/.env; PGPASSWORD="$DB_PASSWORD" psql -X -w -v ON_ERROR_STOP=1 -At -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c `
	if got := strings.TrimSpace(remote(query+shellQuote("SELECT current_user || ':' || count(*) FROM assets;"), 0)); got != "app_service:3" {
		t.Fatalf("real app database connection differs:%s", got)
	}
	remote(query+shellQuote("INSERT INTO assets VALUES(991,'services-component','probe','active');"), 0)
	if got := strings.TrimSpace(remote(query+shellQuote("SELECT hostname FROM assets WHERE id=991;"), 0)); got != "services-component" {
		t.Fatal("SQL mutation did not persist across genuine app SSH channels")
	}
	if got := remote("/usr/local/bin/backup-db", 0); !strings.Contains(got, "Backup completed:") {
		t.Fatalf("real planted backup script did not complete:%s", got)
	}
	backupQuery := `. /srv/app/.env; ssh -i /srv/app/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=/srv/app/.ssh/known_hosts "$BACKUP_USER@$BACKUP_HOST" `
	remote(backupQuery+shellQuote(`set -eu; for file in /srv/backups/*/*.sql.gz; do gzip -t "$file"; gzip -cd "$file" | grep -q services-component; done; printf backup-verified`), 0)
	// A valid but WRONG app public key must not be accepted as the backup's key.
	remote(`cp /srv/app/.ssh/known_hosts /tmp/component-original-hosts; printf 'backup %s\n' "$(cut -d' ' -f1-2 /run/sshd/bootstrap/keys/ssh_host_ed25519_key.pub)" > /srv/app/.ssh/known_hosts`, 0)
	remote("/usr/local/bin/backup-db", 255)
	remote("cp /tmp/component-original-hosts /srv/app/.ssh/known_hosts; /usr/local/bin/backup-db", 0)
	t.Log("actual app SQL mutation -> planted pg_dump/gzip/strict-key SSH backup -> remote readback passed in a shared network-none namespace; production routing/isolation/reset is a separate gate")
}
