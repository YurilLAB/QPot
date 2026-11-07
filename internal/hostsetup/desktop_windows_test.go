//go:build windows

package hostsetup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// fakeDesktopEnv makes the test binary, started as "Docker Desktop.exe",
// stand in for Docker Desktop: it writes "started" next to the marker path
// in this variable, keeps running a while as the real one does, then writes
// "done" and exits.
const fakeDesktopEnv = "QPOT_TEST_FAKE_DESKTOP"

func TestMain(m *testing.M) {
	if dir := os.Getenv(fakeDesktopEnv); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "started"), nil, 0o600)
		time.Sleep(6 * time.Second)
		_ = os.WriteFile(filepath.Join(dir, "done"), nil, 0o600)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func waitFile(p string, d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// TestDesktopStartReturnsWhileDesktopRuns: Docker Desktop keeps running
// after "cmd /c start" returns. When setup captured the command's output,
// Docker Desktop inherited the pipes and held them open, so the step waited
// for them (20 seconds) and failed although Docker Desktop had started.
func TestDesktopStartReturnsWhileDesktopRuns(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pf, marks := t.TempDir(), t.TempDir()
	t.Setenv("ProgramFiles", pf)
	exe := desktopExe()
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeDesktopEnv, marks)
	// A short grace for output after the command ends (setup waits 20s):
	// the stand-in outlives it, as Docker Desktop outlives any grace.
	in := &Installer{P: Platform{GOOS: "windows", GOARCH: "amd64"}, R: &ExecRunner{NoTTY: true, Grace: 2 * time.Second}, LookPath: exec.LookPath}
	plan, perr := in.Plan(context.Background(), Need{Start: true})
	if perr != nil {
		t.Fatal(perr)
	}
	st := plan.Steps[0]
	if st.Prepare != nil {
		if e := st.Prepare(context.Background()); e != nil {
			t.Fatalf("prepare with Docker Desktop in place: %v", e)
		}
	}
	start := time.Now()
	res := in.R.Run(context.Background(), st.Cmds[0])
	took := time.Since(start)
	// Let the stand-in finish before its folder is removed.
	defer waitFile(filepath.Join(marks, "done"), 15*time.Second)
	if !waitFile(filepath.Join(marks, "started"), 10*time.Second) {
		t.Fatalf("Docker Desktop was not started (%+v)", res)
	}
	if !res.OK() || took > 2*time.Second {
		t.Fatalf("starting Docker Desktop took %s and ended %+v (err %v); it must return at once and succeed", took.Round(time.Second), res, res.Err)
	}
}

// TestDesktopStartWithoutTheProgram: without Docker Desktop.exe where setup
// looks, "start" would show a dialog and wait for it; setup says what to do
// instead and runs nothing.
func TestDesktopStartWithoutTheProgram(t *testing.T) {
	t.Setenv("ProgramFiles", t.TempDir())
	in := &Installer{P: Platform{GOOS: "windows", GOARCH: "amd64"}, R: &ExecRunner{NoTTY: true}, LookPath: exec.LookPath}
	plan, perr := in.Plan(context.Background(), Need{Start: true})
	if perr != nil {
		t.Fatal(perr)
	}
	start := time.Now()
	e := in.Execute(context.Background(), plan)
	if e == nil || e.Code != "QP-DOCKER-007" || time.Since(start) > 5*time.Second {
		t.Fatalf("Execute without Docker Desktop.exe: %v after %s", e, time.Since(start).Round(time.Second))
	}
}
