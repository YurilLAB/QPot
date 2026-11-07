package instance

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// RestartHoneypot runs `docker compose restart` for the honeypot and its
// companions only, and passes no unknown name to docker.
func TestRestartHoneypotArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\ncase \"$*\" in *fail-me*) echo boom >&2; exit 1 ;; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test stand-in must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := settingsTestConfig(t, "restart-argv")
	cfg.Security.SandboxMode = "none"
	cfg.EnableHoneypot("ssh-proxy")
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := m.RestartHoneypot(ctx, "ssh-proxy"); err != nil {
		t.Fatal(err)
	}
	if err := m.RestartHoneypot(ctx, "--project-name=fail-me"); err == nil || !strings.Contains(err.Error(), "unknown honeypot") {
		t.Fatalf("unknown name: %v", err)
	}
	data, _ := os.ReadFile(log)
	want := "compose -f " + cfg.GetDockerComposePath() + " restart ssh-proxy ssh-backend-1 ssh-backend-2\n"
	if string(data) != want {
		t.Fatalf("docker calls:\n%q\nwant\n%q", data, want)
	}
}
