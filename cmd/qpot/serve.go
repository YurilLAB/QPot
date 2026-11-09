package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/server"
	"github.com/spf13/cobra"
)

// loadInstance loads an instance's config with its QPot ID filled in,
// generating and saving the ID on first use.
func loadInstance(name string) (*config.Config, *instance.QPotID, error) {
	cfg, err := config.Load(name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}
	id, err := instance.LoadID(name)
	if err != nil {
		id, err = instance.GenerateID(name)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate QPot ID: %w", err)
		}
		id.DataPath = cfg.DataPath
		if err := id.Save(); err != nil {
			return nil, nil, fmt.Errorf("failed to save QPot ID: %w", err)
		}
	}
	cfg.QPotID = id.ID
	return cfg, id, nil
}

// runControlPlane runs everything QPot does besides the containers - the web
// UI/API, the intelligence worker and alerting (both started by the web
// server), cluster membership and the HiFi backend recycler - until ctx ends.
//
// These previously only started AFTER Manager.Start returned: in foreground
// mode that was at Ctrl+C, and with -d the process exited right away. Either
// way the web UI never served and no event was ever classified.
func runControlPlane(ctx context.Context, cfg *config.Config, mgr *instance.Manager) error {
	server.Version = version
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fatal := make(chan error, 1)

	// The web server shows the cluster this control plane runs (live members,
	// join requests). It and the cluster start independently; whichever is
	// ready second hands the running manager over.
	var (
		attachMu sync.Mutex
		web      *server.Server
		running  *cluster.Manager
	)
	attach := func(w *server.Server, cm *cluster.Manager) {
		attachMu.Lock()
		defer attachMu.Unlock()
		if w != nil {
			web = w
		}
		if cm != nil {
			running = cm
		}
		if web != nil && running != nil {
			web.SetCluster(running)
		}
	}

	// The web server serves at once and reaches the database behind its UI;
	// it runs alongside the recycler and the cluster. The port is
	// claimed-checked up front: a control plane whose web UI cannot bind used
	// to keep running headless, while a health probe of the port reached
	// whatever else held it (typically another instance's web UI).
	if cfg.WebUI.Enabled {
		if err := webPortFree(cfg); err != nil {
			return err
		}
		go func() {
			webSrv, err := server.New(cfg)
			if err != nil {
				fatal <- fmt.Errorf("web server: %w", err)
				return
			}
			attach(webSrv, nil)
			slog.Info("Web server started", "addr", fmt.Sprintf("%s:%d", cfg.WebUI.BindAddr, cfg.WebUI.Port))
			if err := webSrv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fatal <- fmt.Errorf("web server: %w", err)
			}
		}()
	}

	// Cluster membership (gossip, sync and the cluster API) when this node is
	// paired. Only one process per host can own the cluster port; a second
	// instance's control plane just logs that and carries on.
	if dir, err := cluster.DefaultDataPath(); err == nil {
		cm := cluster.NewManager(dir)
		if c, err := cm.LoadCluster(); err == nil && c != nil {
			if err := cm.UnlockFromSecret(); err != nil {
				slog.Warn("Cluster not started", "error", err)
			} else if err := cm.Start(); err != nil {
				slog.Warn("Cluster not started", "error", err)
			} else {
				slog.Info("Cluster membership running", "cluster", c.Name)
				defer func() { _ = cm.Stop() }()
				attach(nil, cm)
			}
		}
	}

	// HiFi: recreate each real-OpenSSH backend after every session.
	rec, err := instance.NewBackendRecycler(cfg)
	if err != nil {
		return err
	}
	if rec != nil {
		go rec.Run(ctx)
		slog.Info("HiFi backend recycler started")
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-fatal:
		slog.Error("Control plane stopping", "error", err)
		return err
	}
}

// webPortFree reports, as an actionable error, that the web UI address is
// already taken.
func webPortFree(cfg *config.Config) error {
	addr := net.JoinHostPort(cfg.WebUI.BindAddr, fmt.Sprint(cfg.WebUI.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web UI address %s is already in use (another QPot instance?): set web_ui.port in %s", addr, cfg.ConfigPath)
	}
	return ln.Close()
}

func newServeCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the QPot control plane (web UI, intelligence, HiFi recycler) for a running instance",
		Long: "Run the QPot control plane for an instance whose containers are already up: the web UI/API, " +
			"the intelligence worker, alerting, cluster membership and the HiFi backend recycler. " +
			"'qpot up -d' starts this in the background; run it directly under a service manager such as systemd.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadInstance(instanceName)
			if err != nil {
				return err
			}
			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}
			// A second control plane would take over the pid file, fail on the
			// web UI port and delete the file on exit, leaving the running one
			// unreachable for `qpot down`.
			if pid := runningServePID(cfg); pid != 0 && pid != os.Getpid() {
				return fmt.Errorf("the control plane of instance %q is already running (pid %d); stop it with: qpot down -i %s",
					cfg.InstanceName, pid, cfg.InstanceName)
			}
			pidPath := servePIDPath(cfg)
			if err := writeServePID(pidPath, os.Getpid()); err != nil {
				return err
			}
			defer removeServePID(pidPath, os.Getpid())
			slog.Info("QPot control plane running", "instance", cfg.InstanceName, "pid", os.Getpid())
			return runControlPlane(cmd.Context(), cfg, mgr)
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

func servePIDPath(cfg *config.Config) string { return filepath.Join(cfg.DataPath, "qpot-serve.pid") }

func writeServePID(path string, pid int) error {
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

// removeServePID deletes the pid file only if it still names this process.
func removeServePID(path string, pid int) {
	if got, err := readServePID(path); err == nil && got == pid {
		_ = os.Remove(path)
	}
}

func readServePID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid file %s", path)
	}
	return pid, nil
}

// runningServePID returns the pid of this instance's background control plane,
// or 0. The pid must still be alive AND be a `qpot serve` for this instance,
// so a stale pid file can never make us signal an unrelated process.
func runningServePID(cfg *config.Config) int {
	path := servePIDPath(cfg)
	pid, err := readServePID(path)
	if err != nil || !processAlive(pid) || !isServeProcess(pid, cfg.InstanceName) {
		return 0
	}
	// A stale pid file (crash, reboot) can name a PID since reused by
	// another program; one that started after the file was written did not
	// write it. Windows has no command line to check, so this is its guard.
	if fi, err := os.Stat(path); err == nil {
		if started, ok := processStartTime(pid); ok && started.After(fi.ModTime().Add(2*time.Second)) {
			return 0
		}
	}
	return pid
}

// startBackgroundServe launches `qpot serve -i <instance>` detached from this
// terminal, logging to <instance>/logs/qpot-serve.log (0600).
func startBackgroundServe(cfg *config.Config) (int, string, error) {
	if pid := runningServePID(cfg); pid != 0 {
		return pid, "", nil
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, "", fmt.Errorf("locate qpot binary: %w", err)
	}
	logDir := filepath.Join(cfg.DataPath, "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return 0, "", err
	}
	logPath := filepath.Join(logDir, "qpot-serve.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, "", err
	}
	defer logFile.Close()
	c := exec.Command(exe, "serve", "-i", cfg.InstanceName)
	c.Stdout, c.Stderr, c.Stdin = logFile, logFile, nil
	detachProcess(c)
	if err := c.Start(); err != nil {
		return 0, "", fmt.Errorf("start background control plane: %w", err)
	}
	pid := c.Process.Pid
	_ = c.Process.Release()
	// Wait for it to register itself (so `qpot down` can find it), then make
	// sure it is still running a moment later: a control plane that cannot
	// start (e.g. its web UI port is taken) exits straight away, and reporting
	// it as running hid that.
	registered := false
	for i := 0; i < 50 && !registered; i++ {
		if got, err := readServePID(servePIDPath(cfg)); err == nil && got == pid {
			registered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if registered {
		for i := 0; i < 15 && registered; i++ {
			time.Sleep(100 * time.Millisecond)
			registered = runningServePID(cfg) == pid
		}
	}
	if !registered {
		return 0, logPath, fmt.Errorf("the control plane exited during startup: %s (log: %s)", lastLogLine(logPath), logPath)
	}
	return pid, logPath, nil
}

// lastLogLine returns the last non-empty line of a log file, for error messages.
func lastLogLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "no log"
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" && !strings.Contains(l, "gvisor sandbox not available") {
			if len(l) > 300 {
				l = l[:300]
			}
			return l
		}
	}
	return "empty log"
}

// stopBackgroundServe stops this instance's background control plane, if any.
func stopBackgroundServe(cfg *config.Config) {
	pid := runningServePID(cfg)
	if pid == 0 {
		return
	}
	terminateProcess(pid)
	for i := 0; i < 50 && processAlive(pid); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(servePIDPath(cfg))
	slog.Info("Stopped QPot control plane", "pid", pid)
}
