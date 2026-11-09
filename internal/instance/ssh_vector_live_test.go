package instance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Exercise the generated VRL with the actual Vector runtime, including delayed
// archived evidence. The database's own session must never become an ingress
// lease ID, and reading captured output must not count as credential reuse.
func TestHiFiVectorEvidenceLive(t *testing.T) {
	dir := t.TempDir()
	runner := vectorRunner(t, dir)
	cfg := enableSSHProxy(t, "hifi-vector")
	enableOnly(cfg, "ssh-proxy")
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: mustSandbox(t, cfg)}).GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Sources map[string]struct {
			Include []string `yaml:"include"`
			Exclude []string `yaml:"exclude"`
		} `yaml:"sources"`
		Transforms map[string]struct{ Source string } `yaml:"transforms"`
	}
	if err := yaml.Unmarshal([]byte(out), &generated); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(generated.Sources["ssh-proxy_logs"].Exclude, "\n"), "/logs/cells/**") {
		t.Fatal("broker source would ingest cell evidence twice")
	}
	includes := strings.Join(generated.Sources["ssh_backend_logs"].Include, "\n")
	if !strings.Contains(includes, "/current/**/*.json") || !strings.Contains(includes, "/archive-g*/logs/**/*.json") {
		t.Fatal("collector must follow current and archived cell evidence")
	}
	harness := map[string]any{
		"data_dir": dir,
		"sources":  map[string]any{"in": map[string]any{"type": "stdin"}},
		"transforms": map[string]any{
			"split":     map[string]any{"type": "remap", "inputs": []string{"in"}, "source": "parts = split(string!(.message), \"\\t\", 2)\n.file = parts[0]\n.message = parts[1]\n"},
			"normalise": map[string]any{"type": "remap", "inputs": []string{"split"}, "source": generated.Transforms["add_qpot_metadata"].Source},
		},
		"sinks": map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"normalise"}, "path": filepath.Join(dir, "events.json"), "encoding": map[string]any{"codec": "json"}}},
	}
	data, err := yaml.Marshal(harness)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "vector.yaml")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	const base = "/data/honeypots/ssh-proxy/logs/cells/"
	input := strings.Join([]string{
		base + "ssh-backend-1/current/0/events.json\t" + `{"timestamp":"2026-11-09T00:00:01Z","event_type":"ssh_backend_command_start","src_ip":"203.0.113.24","src_port":40001,"peer_ip":"172.25.0.2","peer_port":51000,"session_id":"outer-1","session":"capture-1","generation":7,"username":"root","uid":0,"phase":"start","input":"hostname","attribution":"broker_context","file":"/data/honeypots/evil/logs/events.json","cell":"evil","role":"evil"}`,
		base + "ssh-backend-1/archive-g7-Ab12/logs/0/events.json\t" + `{"timestamp":"2026-11-09T00:00:02Z","event_type":"ssh_backend_command","src_ip":"203.0.113.24","src_port":40001,"session_id":"outer-1","session":"capture-1","generation":7,"phase":"finish","input":"hostname","exit_code":0,"duration_ms":3,"stdout":"sensitive-response-only","stdout_file":"0/capture-1.stdout","truncated":false}`,
		base + "ssh-backend-2-backup/current/1000/events.json\t" + `{"event_type":"ssh_backend_command","src_ip":"172.26.0.10","src_port":40002,"input":"ls /srv/backups","session_id":"outer-2","generation":4,"phase":"finish","exit_code":1,"attribution":"broker_context","attribution_error":"","stderr":"response-only"}`,
		base + "ssh-backend-1-db/archive-g7-X9/logs/queries.json\t" + `{"timestamp":"2026-11-09T00:00:03Z","remote_host":"172.25.0.10","remote_port":41000,"user":"postgres","session_id":"pg-123","message":"statement: SELECT * FROM assets","cell":"forged"}`,
		// The broker's connect record only joins sessions on the host; its
		// cell reset request names no visitor, so it never becomes an event.
		"/data/honeypots/ssh-proxy/logs/broker/sessions.json\t" + `{"timestamp":"2026-11-09T00:00:00Z","event_type":"ssh_proxy_connect","honeypot":"ssh-proxy","src_ip":"203.0.113.24","src_port":40001,"backend":"ssh-backend-1","session_id":"outer-1","generation":7,"backend_port":51000}`,
		"/data/honeypots/ssh-proxy/logs/broker/sessions.json\t" + `{"timestamp":"2026-11-09T00:30:00Z","event_type":"ssh_proxy_cell_reset","honeypot":"ssh-proxy","src_ip":"","src_port":0,"backend":"ssh-backend-1","generation":7,"reason":"cell_hold_expired"}`,
		// Startup/health checks, malformed paths and unrelated guest JSON are dropped.
		base + "ssh-backend-1-db/current/queries.json\t" + `{"remote_host":"127.0.0.1","message":"statement: SELECT 1"}`,
		base + "ssh-backend-1-db/current/queries.json\t" + `{"remote_host":"","message":"database system is ready"}`,
		base + "ssh-backend-17/current/events.json\t" + `{"event_type":"ssh_backend_command","src_ip":"203.0.113.4"}`,
		base + "ssh-backend-1/current/events.json\t" + `{"event_type":"forged","src_ip":"203.0.113.4"}`,
	}, "\n") + "\n"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runner[0], append(runner[1:], "--quiet", "--config", configPath)...)
	cmd.Stdin = strings.NewReader(input)
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		t.Fatalf("Vector failed: %v\n%s", err, diagnostics.String())
	}
	f, err := os.Open(filepath.Join(dir, "events.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type event struct {
		Honeypot string            `json:"honeypot"`
		Type     string            `json:"event_type"`
		IP       string            `json:"source_ip"`
		Port     int               `json:"source_port"`
		DestPort int               `json:"dest_port"`
		Session  string            `json:"session_id"`
		Command  string            `json:"command"`
		Metadata map[string]string `json:"metadata"`
	}
	var rows []event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var row event
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d events, want four valid native observations: %+v\n%s", len(rows), rows, diagnostics.String())
	}
	for _, row := range rows {
		if row.Honeypot != "ssh-proxy" || row.Metadata["state_scope"] != "private_cell" || strings.Contains(row.Metadata["cell"], "forged") {
			t.Errorf("untrusted source attribution: %+v", row)
		}
		for _, field := range []string{"stdout", "stderr", "response"} {
			if _, present := row.Metadata[field]; present {
				t.Errorf("response text copied to watched metadata: %s", field)
			}
		}
	}
	if r := rows[0]; r.Type != "ssh-proxy.command.start" || r.IP != "203.0.113.24" || r.Port != 40001 || r.Session != "outer-1" || r.Metadata["cell"] != "ssh-backend-1" || r.Metadata["generation"] != "7" || r.Metadata["role"] != "app" {
		t.Errorf("incorrect start correlation: %+v", r)
	}
	if r := rows[1]; r.Type != "ssh-proxy.command.finish" || r.Session != rows[0].Session || r.Metadata["exit_code"] != "0" || r.Metadata["stdout_file"] != "0/capture-1.stdout" || r.Metadata["capture_id"] != rows[0].Metadata["capture_id"] || r.Metadata["capture_id"] != "capture-1" {
		t.Errorf("incorrect archived finish correlation: %+v", r)
	}
	if r := rows[2]; r.Metadata["role"] != "backup" || r.Metadata["cell"] != "ssh-backend-2" || r.Metadata["exit_code"] != "1" {
		t.Errorf("incorrect backup role: %+v", r)
	}
	if r := rows[3]; r.Type != "ssh-proxy.database.statement" || r.IP != "172.25.0.10" || r.DestPort != 5432 || r.Command != "SELECT * FROM assets" || r.Session != "" || r.Metadata["pg_session_id"] != "pg-123" || r.Metadata["role"] != "database" {
		t.Errorf("database query misattributed: %+v", r)
	}
}
