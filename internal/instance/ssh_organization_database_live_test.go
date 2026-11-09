package instance

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"
)

// This is an isolated component gate. Networking is disabled, no ports are
// published. Its process, identity, security, storage and resource/log settings
// come from the generated DB service. It does not bypass or validate the full
// environment's mandatory guard.
func TestSSHOrganizationDatabaseLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_HIFI_DATABASE") != "1" {
		t.Skip("set QPOT_TEST_HIFI_DATABASE=1 with the pinned PostgreSQL image cached")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg := config.Default(fmt.Sprintf("hifi-db-%d", time.Now().UnixNano()))
	cfg.QPotID = "qp_hifidatabase000000000001"
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	cfg.Security.SandboxMode = "none"
	enableOnly(cfg, sshProxyHoneypot)
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.CustomConfig = map[string]string{"backends": "1", "environment": "organization", "image_source": "local"}
	cfg.Honeypots[sshProxyHoneypot] = hp
	run := func(input []byte, args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, "docker", args...)
		command.Stdin = bytes.NewReader(input)
		return command.CombinedOutput()
	}
	if output, err := run(nil, "image", "inspect", sshOrganizationDBImage); err != nil {
		t.Fatalf("pull the exact production PostgreSQL image before this component gate: %v\n%s", err, output)
	}
	prepareSSHStoreForTest(t, cfg)
	if err := prepareSSHOrganization(cfg); err != nil {
		t.Fatal(err)
	}
	cell := requireSSHOrgCells(t, cfg)[0]
	var compose struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &compose); err != nil {
		t.Fatal(err)
	}
	var database struct {
		Image, User, Hostname, Restart string
		ReadOnly                       bool `yaml:"read_only"`
		Command, Volumes, Tmpfs, DNS   []string
		CapDrop                        []string `yaml:"cap_drop"`
		SecurityOpt                    []string `yaml:"security_opt"`
		Environment                    map[string]string
		Logging                        struct {
			Driver  string
			Options map[string]string
		}
		Deploy struct {
			Resources struct {
				Limits struct {
					CPUs, Memory string
					Pids         int
				}
			}
		}
	}
	databaseNode := compose.Services[cell.Database]
	if err := databaseNode.Decode(&database); err != nil {
		t.Fatal(err)
	}
	if database.Image != sshOrganizationDBImage || database.User != "999:999" || !database.ReadOnly || len(database.Tmpfs) != 3 {
		t.Fatal("component did not select the actual production database security/storage configuration")
	}
	name := cfg.InstanceName + "-component"
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if t.Failed() {
			output, _ := exec.CommandContext(cleanupCtx, "docker", "logs", "--tail", "60", name).CombinedOutput()
			t.Logf("owned PostgreSQL component diagnostics:\n%s", output)
		}
		if output, err := exec.CommandContext(cleanupCtx, "docker", "rm", "-f", "-v", name).CombinedOutput(); err != nil {
			t.Logf("owned PostgreSQL component cleanup (%v): %s", err, output)
		}
	})
	args := []string{"run", "-d", "--name", name, "--network", "none", "--read-only", "--user", database.User, "--hostname", database.Hostname}
	for _, capability := range database.CapDrop {
		args = append(args, "--cap-drop", capability)
	}
	for _, option := range database.SecurityOpt {
		args = append(args, "--security-opt", option)
	}
	for _, filesystem := range database.Tmpfs {
		args = append(args, "--tmpfs", filesystem)
	}
	for _, volume := range database.Volumes {
		args = append(args, "--volume", volume)
	}
	for _, resolver := range database.DNS {
		args = append(args, "--dns", resolver)
	}
	for key, value := range database.Environment {
		args = append(args, "--env", key+"="+value)
	}
	if database.Restart != "" {
		args = append(args, "--restart", database.Restart)
	}
	limits := database.Deploy.Resources.Limits
	args = append(args, "--memory", limits.Memory, "--cpus", limits.CPUs)
	if limits.Pids > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(limits.Pids))
	}
	args = append(args, "--log-driver", database.Logging.Driver)
	for key, value := range database.Logging.Options {
		args = append(args, "--log-opt", key+"="+value)
	}
	args = append(append(args, database.Image), database.Command...)
	if output, err := run(nil, args...); err != nil {
		t.Fatalf("start exact PostgreSQL component with networking disabled: %v\n%s", err, output)
	}
	output, err := run(nil, "inspect", name)
	if err != nil {
		t.Fatal(err)
	}
	var inspected []struct {
		HostConfig struct {
			NetworkMode    string
			ReadonlyRootfs bool
			PortBindings   map[string]any
		}
	}
	if json.Unmarshal(output, &inspected) != nil || len(inspected) != 1 || inspected[0].HostConfig.NetworkMode != "none" || !inspected[0].HostConfig.ReadonlyRootfs || len(inspected[0].HostConfig.PortBindings) != 0 {
		t.Fatal("PostgreSQL component unexpectedly has networking, published ports or a writable root")
	}
	sshLiveWait(t, ctx, "isolated PostgreSQL initialization", func() bool {
		_, err := run(nil, "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", cell.DBUsername, "-d", cell.DBName)
		return err == nil
	})
	organization := newSSHOrganization(cfg)
	psql := func(user, password, db, query string, input []byte) string {
		t.Helper()
		arguments := []string{"exec", "-i", "--env", "PGPASSWORD=" + password, name, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-At", "-h", "127.0.0.1", "-U", user, "-d", db}
		if query != "" {
			arguments = append(arguments, "-c", query)
		}
		output, err := run(input, arguments...)
		if err != nil {
			t.Fatalf("isolated real psql failed: %v\n%s", err, output)
		}
		return strings.TrimSpace(string(output))
	}
	query := func(sql string) string {
		return psql(organization.dbUser, organization.dbPassword, cell.DBName, sql, nil)
	}
	version, err := strconv.Atoi(query("SHOW server_version_num;"))
	if err != nil || version < 150000 || version >= 160000 {
		t.Fatalf("pinned database did not run real PostgreSQL15: %d %v", version, err)
	}
	if got := query("SELECT current_setting('log_statement') || ':' || current_setting('log_destination') || ':' || current_setting('logging_collector');"); got != "all:jsonlog:on" {
		t.Fatalf("production SQL observation configuration was not applied: %s", got)
	}
	if got := query("SELECT current_database() || ':' || current_user || ':' || (SELECT count(*) FROM assets);"); got != cell.DBName+":"+organization.dbUser+":3" {
		t.Fatalf("generated database/role/seed mismatch: %s", got)
	}
	if got := query("SELECT rolsuper::text || ':' || rolcreaterole::text FROM pg_roles WHERE rolname=current_user;"); got != "false:false" {
		t.Fatalf("planted service account unexpectedly has administrative role rights: %s", got)
	}
	// Official PostgreSQL initializes trusted local sockets/loopback separately
	// from peer authentication. Verify the actual role's stored SCRAM verifier
	// against the planted password without claiming a peer-network login here.
	verifier := psql(cell.DBUsername, cell.DBPassword, cell.DBName, "SELECT rolpassword FROM pg_authid WHERE rolname='app_service';", nil)
	if !sshDatabasePasswordMatchesSCRAM(organization.dbPassword, verifier) || sshDatabasePasswordMatchesSCRAM(organization.dbPassword+"-incorrect", verifier) {
		t.Fatal("real PostgreSQL password verifier differs from the planted credential")
	}
	query("UPDATE assets SET status='component-state-probe' WHERE id=1; INSERT INTO assets VALUES (991,'component-host','probe','active');")
	if got := query("SELECT status || ':' || (SELECT count(*) FROM assets WHERE id=991) FROM assets WHERE id=1;"); got != "component-state-probe:1" {
		t.Fatal("a later real SQL connection did not observe the mutation")
	}
	dump, err := run(nil, "exec", "--env", "PGPASSWORD="+organization.dbPassword, name, "pg_dump", "--no-owner", "--no-privileges", "-h", "127.0.0.1", "-U", organization.dbUser, cell.DBName)
	if err != nil || !bytes.Contains(dump, []byte("component-state-probe")) || !bytes.Contains(dump, []byte("component-host")) {
		t.Fatalf("genuine pg_dump did not contain mutated data: %v", err)
	}
	psql(cell.DBUsername, cell.DBPassword, cell.DBName, "CREATE DATABASE component_restore OWNER app_service;", nil)
	psql(organization.dbUser, organization.dbPassword, "component_restore", "", dump)
	if got := psql(organization.dbUser, organization.dbPassword, "component_restore", "SELECT count(*) FROM assets WHERE id=991;", nil); got != "1" {
		t.Fatal("real SQL dump did not restore consistently")
	}
	var observation map[string]any
	sshLiveWait(t, ctx, "native PostgreSQL JSON query record", func() bool {
		output, err := run(nil, "exec", name, "sh", "-c", "cat /var/log/postgresql/*.json")
		if err != nil {
			return false
		}
		for _, line := range bytes.Split(output, []byte("\n")) {
			var event map[string]any
			if json.Unmarshal(line, &event) == nil {
				if message, _ := event["message"].(string); strings.HasPrefix(message, "statement: UPDATE assets") && strings.Contains(message, "component-state-probe") {
					observation = event
					return true
				}
			}
		}
		return false
	})
	remote, _ := observation["remote_host"].(string)
	port, _ := observation["remote_port"].(float64)
	session, _ := observation["session_id"].(string)
	timestamp, _ := observation["timestamp"].(string)
	if !net.ParseIP(remote).IsLoopback() || port < 1 || port > 65535 || observation["user"] != organization.dbUser || observation["dbname"] != cell.DBName || session == "" || timestamp == "" {
		t.Fatalf("native PostgreSQL JSON fields do not fit the collector contract: %+v", observation)
	}
	observedJSON, _ := json.Marshal(observation)
	t.Logf("native isolated PostgreSQL statement JSON: %s", observedJSON)
	sshDatabaseLogVectorCompatibility(t, cfg, observation)
	t.Log("production PostgreSQL component passed: network-none/read-only UID999, matching SCRAM credential, seeded real SQL mutations, genuine dump/restore and native JSON collector compatibility")
}

func sshDatabasePasswordMatchesSCRAM(password, verifier string) bool {
	parts := strings.Split(verifier, "$")
	if len(parts) != 3 || parts[0] != "SCRAM-SHA-256" {
		return false
	}
	iterations, salt, ok := strings.Cut(parts[1], ":")
	count, err := strconv.Atoi(iterations)
	if !ok || err != nil || count < 1 || count > 1_000_000 {
		return false
	}
	decodedSalt, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}
	stored, server, ok := strings.Cut(parts[2], ":")
	if !ok {
		return false
	}
	salted := pbkdf2.Key([]byte(password), decodedSalt, count, sha256.Size, sha256.New)
	mac := hmac.New(sha256.New, salted)
	_, _ = mac.Write([]byte("Client Key"))
	storedKey := sha256.Sum256(mac.Sum(nil))
	mac.Reset()
	_, _ = mac.Write([]byte("Server Key"))
	return hmac.Equal([]byte(stored), []byte(base64.StdEncoding.EncodeToString(storedKey[:]))) && hmac.Equal([]byte(server), []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil))))
}

func sshDatabaseLogVectorCompatibility(t *testing.T, cfg *config.Config, observed map[string]any) {
	t.Helper()
	directory := t.TempDir()
	runner := vectorRunner(t, directory)
	if filepath.Base(runner[0]) == "docker" {
		// The compatibility normalizer has only stdin/file I/O too.
		runner = append([]string{runner[0], "run", "--network", "none"}, runner[2:]...)
	}
	configuration, err := (&ComposeGenerator{Config: cfg, Sandbox: mustSandbox(t, cfg)}).GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Transforms map[string]struct{ Source string }
	}
	if err := yaml.Unmarshal([]byte(configuration), &generated); err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(observed)
	// Only this in-memory normalization control changes the source address.
	// No socket is opened to the documentation address; actual PG traffic
	// above remains on loopback in its network-none container.
	copy := make(map[string]any, len(observed))
	for key, value := range observed {
		copy[key] = value
	}
	copy["remote_host"] = "198.51.100.77"
	peer, _ := json.Marshal(copy)
	path := "/data/honeypots/ssh-proxy/logs/cells/ssh-backend-1-db/current/queries-test.json"
	input := path + "\t" + string(original) + "\n" + path + "\t" + string(peer) + "\n"
	outputPath := filepath.Join(directory, "normalized.json")
	harness := map[string]any{"data_dir": directory, "sources": map[string]any{"in": map[string]any{"type": "stdin"}},
		"transforms": map[string]any{"split": map[string]any{"type": "remap", "inputs": []string{"in"}, "source": "parts = split(string!(.message), \"\\t\", 2)\n.file = parts[0]\n.message = parts[1]\n"},
			"normalize": map[string]any{"type": "remap", "inputs": []string{"split"}, "source": generated.Transforms["add_qpot_metadata"].Source}},
		"sinks": map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"normalize"}, "path": outputPath, "encoding": map[string]any{"codec": "json"}}}}
	encoded, _ := yaml.Marshal(harness)
	configPath := filepath.Join(directory, "vector.yaml")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, runner[0], append(runner[1:], "--quiet", "--config", configPath)...)
	command.Stdin = strings.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual PostgreSQL record failed native Vector normalization: %v\n%s", err, output)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
	var event map[string]any
	if len(lines) != 1 || json.Unmarshal(lines[0], &event) != nil || event["src_ip"] != "198.51.100.77" || event["eventid"] != "ssh-proxy.database.statement" || event["protocol"] != "postgresql" || event["username"] != observed["user"] {
		t.Fatalf("loopback was not ignored or native JSON normalization changed: %s", output)
	}
}
