package instance

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/sshcapture"
)

// The drain converts every backend it can and names the ones it could not;
// a backend with no container has nothing to convert.
func TestDrainConvertsWhatItCanAndReportsTheRest(t *testing.T) {
	cfg := organizationTestConfig(t)
	prepareSSHStoreForTest(t, cfg)
	for _, service := range []string{"ssh-backend-1", "ssh-backend-2"} {
		if err := prepareSSHLogDir(cfg.DataPath, service); err != nil {
			t.Fatal(err)
		}
	}
	converter := &sshcapture.Converter{
		Inspect: func(_ context.Context, name string) (sshcapture.Container, error) {
			if strings.HasSuffix(name, "_ssh-backend-3") {
				return sshcapture.Container{}, nil
			}
			return sshcapture.Container{ID: name + "-id", Created: time.Now().Add(-time.Hour)}, nil
		},
		Stream: func(_ context.Context, id string, _ bool) (io.ReadCloser, io.ReadCloser, func() error, error) {
			if strings.HasSuffix(id, "_ssh-backend-1-id") {
				return nil, nil, nil, errors.New("the daemon is unavailable")
			}
			return io.NopCloser(strings.NewReader("")), io.NopCloser(strings.NewReader("Accepted password for root from 172.30.0.10 port 40000 ssh2\r\n")), func() error { return nil }, nil
		},
	}
	brokerLog := filepath.Join(t.TempDir(), "sessions.json")
	err := drainSSHCapturesWith(t.Context(), converter, cfg.DataPath, cfg.InstanceName, brokerLog,
		[]string{"ssh-backend-1", "ssh-backend-1-db", "ssh-backend-2", "ssh-backend-3"})
	if err == nil || !strings.Contains(err.Error(), "ssh-backend-1: ") || strings.Contains(err.Error(), "ssh-backend-2") || strings.Contains(err.Error(), "ssh-backend-3") {
		t.Fatalf("drain did not name exactly the backend it could not convert: %v", err)
	}
	dir, err := sshBackendLogDirAt(cfg.DataPath, "ssh-backend-2")
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, sshcapture.AuthLog)); err != nil || !strings.Contains(string(data), "Accepted password") {
		t.Fatalf("one backend's failure stopped the others' conversion: %v %q", err, data)
	}
	if err := drainSSHCapturesWith(t.Context(), converter, cfg.DataPath, cfg.InstanceName, brokerLog, []string{"ssh-backend-3"}); err != nil {
		t.Fatalf("a backend without a container failed the drain: %v", err)
	}
}

// Removing a backend container loses the sessions only its log holds. When
// they cannot be converted, every path that removes cells keeps them: the
// reset neither archives nor recreates, deployment and retirement remove
// nothing, and stopping the instance takes nothing down.
func TestSSHCellRemovalKeepsUnconvertedContainers(t *testing.T) {
	for _, path := range []string{"reset", "deploy", "stop", "retire"} {
		for _, convertible := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/logs fail", true: "/logs read"}[convertible], func(t *testing.T) {
				cfg := organizationTestConfig(t)
				trace := organizationFakeDocker(t)
				prepareSSHStoreForTest(t, cfg)
				cells := 1
				if path == "retire" {
					cells = 2
				}
				compose := organizationComposeFixture(t, cfg.InstanceName, cells, true)
				if err := os.WriteFile(cfg.GetDockerComposePath(), compose, 0o600); err != nil {
					t.Fatal(err)
				}
				for _, service := range SSHCellLogServices()[:3*cells] {
					if err := prepareSSHLogDir(cfg.DataPath, service); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("SSH_TEST_CONTAINER", "1")
				if !convertible {
					t.Setenv("SSH_TEST_LOGS_EXIT", "7")
				}
				manager, err := NewManager(cfg)
				if err != nil {
					t.Fatal(err)
				}
				recycler := requireBackendRecycler(t, cfg)
				removal := "rm"
				switch path {
				case "reset":
					err = recycler.composeRecreate(t.Context(), "ssh-backend-1")
					removal = "up"
				case "deploy":
					err = manager.prepareSSHDeployment(t.Context())
				case "stop":
					err = manager.Stop(t.Context())
					removal = "down"
				case "retire":
					hp := cfg.Honeypots[sshProxyHoneypot]
					hp.CustomConfig["backends"] = "1"
					cfg.Honeypots[sshProxyHoneypot] = hp
					err = retireSSHCells(t.Context(), cfg, compose)
				}
				commands, _ := os.ReadFile(trace)
				if !strings.Contains(string(commands), "\nlogs\n") {
					t.Fatalf("%s removed cells without reading their capture: %v\n%s", path, err, commands)
				}
				archives, _ := filepath.Glob(filepath.Join(filepath.Dir(requireSSHLogDir(t, cfg, "ssh-backend-1")), "archive-g*"))
				if !convertible {
					if err == nil || !strings.Contains(err.Error(), "not yet converted") {
						t.Fatalf("%s carried on after a failed conversion: %v", path, err)
					}
					if strings.Contains(string(commands), "\n"+removal+"\n") || len(archives) != 0 || recycler.generation("ssh-backend-1") != 0 {
						t.Fatalf("%s removed or archived unconverted cells (archives %v):\n%s", path, archives, commands)
					}
					return
				}
				if err != nil && strings.Contains(err.Error(), "not yet converted") {
					t.Fatalf("%s reported a conversion failure with readable logs: %v", path, err)
				}
				// The control: with readable logs the path goes on to its
				// archive or removal (a reset stops later, at the fixture's
				// unverifiable images, after archiving).
				if path == "reset" {
					if len(archives) == 0 {
						t.Fatalf("reset did not archive after a successful conversion: %v", err)
					}
				} else if !strings.Contains(string(commands), "\n"+removal+"\n") {
					t.Fatalf("%s did not remove the cells after a successful conversion: %v\n%s", path, err, commands)
				}
			})
		}
	}
}
