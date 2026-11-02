package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/server"
	"github.com/qpot/qpot/internal/ypanel"
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
// server), the ypanel agent and the HiFi backend recycler - until ctx ends.
//
// These previously only started AFTER Manager.Start returned: in foreground
// mode that was at Ctrl+C, and with -d the process exited right away. Either
// way the web UI never served and no event was ever classified.
func runControlPlane(ctx context.Context, cfg *config.Config, mgr *instance.Manager) {
	if cfg.WebUI.Enabled {
		if webSrv, err := server.New(cfg); err != nil {
			slog.Warn("Failed to create web server", "error", err)
		} else {
			go func() {
				if err := webSrv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("Web server error", "error", err)
				}
			}()
			slog.Info("Web server started", "addr", fmt.Sprintf("%s:%d", cfg.WebUI.BindAddr, cfg.WebUI.Port))
		}
	}

	// ypanel phone-home agent: a construction failure is logged but never
	// blocks QPot.
	if ag, err := ypanel.New(cfg, mgr, version); err != nil {
		slog.Warn("ypanel agent disabled due to error", "error", err)
	} else if ag != nil {
		go func() {
			if err := ag.Run(ctx); err != nil {
				slog.Error("ypanel agent error", "error", err)
			}
		}()
	}

	// HiFi: recreate each real-OpenSSH backend after every session.
	if rec := instance.NewBackendRecycler(cfg); rec != nil {
		go rec.Run(ctx)
		slog.Info("HiFi backend recycler started")
	}

	<-ctx.Done()
}

func newServeCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the QPot control plane (web UI, intelligence, HiFi recycler) for a running instance",
		Long: "Run the QPot control plane for an instance whose containers are already up: the web UI/API, " +
			"the intelligence worker, alerting, the ypanel agent and the HiFi backend recycler. " +
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
			pidPath := servePIDPath(cfg)
			if err := writeServePID(pidPath, os.Getpid()); err != nil {
				return err
			}
			defer removeServePID(pidPath, os.Getpid())
			slog.Info("QPot control plane running", "instance", cfg.InstanceName, "pid", os.Getpid())
			runControlPlane(cmd.Context(), cfg, mgr)
			return nil
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
	pid, err := readServePID(servePIDPath(cfg))
	if err != nil || !processAlive(pid) || !isServeProcess(pid, cfg.InstanceName) {
		return 0
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
	// Wait briefly for it to register itself, so `qpot down` can find it.
	for i := 0; i < 50; i++ {
		if got, err := readServePID(servePIDPath(cfg)); err == nil && got == pid {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return pid, logPath, nil
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
