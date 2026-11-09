package instance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/proxy"
	"github.com/qpot/qpot/internal/sshcapture"
)

// Each HiFi backend's own sshd records its sessions on the container's error
// stream (docker/ssh-backend/openssh); nothing in the guest writes evidence.
// The control plane turns that stream into the cell's evidence files: live
// while it runs, and in full before anything removes a backend container,
// since a removed container's stream is gone.

// sshCaptureService reports whether a cell service runs a backend sshd (the
// app or its backup host; a cell database records nothing).
func sshCaptureService(service string) bool {
	app := sshCellApp(service)
	return app != "" && (service == app || service == app+"-backup")
}

// sshBrokerSessionLog is the broker's event log, which joins a backend's
// sessions to the visitor connections that reached it.
func sshBrokerSessionLog(cfg *config.Config) (string, error) {
	dir, err := sshBrokerLogDir(cfg)
	return filepath.Join(dir, "sessions.json"), err
}

func sshCaptureTarget(dataPath, instanceName string, index *sshcapture.BrokerIndex, service string) sshcapture.Target {
	app := sshCellApp(service)
	return sshcapture.Target{
		Service:   service,
		Container: instanceName + "_" + service,
		Dir:       func() (string, error) { return sshBackendLogDirAt(dataPath, service) },
		Attribute: index.Attributor(app, service == app),
	}
}

func sshCellsLock(dataPath string) sshcapture.Lock {
	return func(ctx context.Context) (func(), error) {
		lock, err := lockSSHFolders(ctx, dataPath)
		if err != nil {
			return nil, err
		}
		return func() { _ = lock.Close() }, nil
	}
}

// RunCapture follows every backend in the instance's current layout until
// ctx ends, converting its sessions into its cell's current log folder. A
// follower replays its container from the first line, so restarting the
// control plane neither loses nor repeats evidence.
func (r *BackendRecycler) RunCapture(ctx context.Context) {
	dataPath := filepath.Dir(r.ComposeFile)
	index := sshcapture.NewBrokerIndex(r.LogPath)
	converter := sshcapture.DockerConverter(sshCellsLock(dataPath))
	following := map[string]bool{}
	var heartbeatFailing bool
	for {
		// The broker admits connections only while this keeps changing.
		if err := writeCaptureHeartbeat(r.GenerationDir); err != nil {
			if !heartbeatFailing {
				slog.Warn("The HiFi broker cannot see that sessions are being converted; it takes no new connections", "error", err)
			}
			heartbeatFailing = true
		} else {
			heartbeatFailing = false
		}
		if layout, err := readSSHLayout(r.ComposeFile, r.InstanceName); err == nil {
			for _, members := range layout.Groups {
				for _, service := range members {
					if sshCaptureService(service) && !following[service] {
						following[service] = true
						go converter.Follow(ctx, sshCaptureTarget(dataPath, r.InstanceName, index, service))
					}
				}
			}
		}
		timer := time.NewTimer(captureHeartbeatEvery)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// captureHeartbeatEvery is how often RunCapture beats: well inside
// proxy.CaptureStale, so a slow beat never turns visitors away.
const captureHeartbeatEvery = 5 * time.Second

// writeCaptureHeartbeat rewrites the converter's heartbeat in the broker's
// read-only generations folder, atomically, with a value that changes.
func writeCaptureHeartbeat(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, proxy.CaptureHeartbeat+".*")
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(tmp, "%d\n", time.Now().UnixNano())
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	// Readable by the broker's non-root user; holds no secret.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, proxy.CaptureHeartbeat))
}

// drainSSHCaptures converts what stopped backends still hold into their
// current folders, before a reset archives the folders or anything removes
// the containers. The caller holds the cells lock. It converts every service
// it can; an error means some sessions are still only in a container's log,
// so the caller must keep that container: removing it would lose them.
func drainSSHCaptures(ctx context.Context, dataPath, instanceName, brokerLog string, services []string) error {
	return drainSSHCapturesWith(ctx, sshcapture.DockerConverter(nil), dataPath, instanceName, brokerLog, services)
}

func drainSSHCapturesWith(ctx context.Context, converter *sshcapture.Converter, dataPath, instanceName, brokerLog string, services []string) error {
	var index *sshcapture.BrokerIndex
	var failed []error
	for _, service := range services {
		if !sshCaptureService(service) {
			continue
		}
		if index == nil {
			index = sshcapture.NewBrokerIndex(brokerLog)
		}
		if err := converter.Drain(ctx, sshCaptureTarget(dataPath, instanceName, index, service)); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", service, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("SSH sessions not yet converted stay in their stopped containers: %w", errors.Join(failed...))
	}
	return nil
}
