package refrigeration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func persistenceTestConfig(root, seed, profile string, clock *time.Time) Config {
	return Config{ListenAddr: "127.0.0.1:0", DeviceSeed: seed, SiteProfile: profile,
		StateDir: filepath.Join(root, "state"), EventLog: filepath.Join(root, "logs", "events.json"),
		Now: func() time.Time { return *clock }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func persistenceCopy(t *testing.T, p plant) plant {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var copied plant
	if err := json.Unmarshal(data, &copied); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestPersistenceRestartAndProfileSwitchRestoreSeparateScenes(t *testing.T) {
	root := t.TempDir()
	clock := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	seed := "persistence-scene-seed"
	retail, err := New(persistenceTestConfig(root, seed, "retail", &clock))
	if err != nil {
		t.Fatal(err)
	}
	retail.plant.Devices[0].Setpoint = -22
	clock = clock.Add(2 * time.Minute)
	if err := retail.tick(); err != nil {
		t.Fatal(err)
	}
	retailWant := persistenceCopy(t, retail.plant)
	if err := retail.Close(); err != nil {
		t.Fatal(err)
	}

	plasma, err := New(persistenceTestConfig(root, seed, "plasma", &clock))
	if err != nil {
		t.Fatal(err)
	}
	if len(plasma.plant.Devices) != 2 || plasma.plant.Devices[0].Setpoint != -30 || plasma.plant.Identity == retailWant.Identity {
		t.Fatal("switching profiles reused the retail scene")
	}
	plasma.plant.Devices[0].Setpoint = -35
	clock = clock.Add(time.Minute)
	if err := plasma.tick(); err != nil {
		t.Fatal(err)
	}
	plasmaWant := persistenceCopy(t, plasma.plant)
	if err := plasma.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		profile string
		want    plant
	}{{"retail", retailWant}, {"plasma", plasmaWant}} {
		s, err := New(persistenceTestConfig(root, seed, tc.profile, &clock))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(s.plant, tc.want) {
			t.Fatalf("%s restart changed stored process/history: got %+v want %+v", tc.profile, s.plant, tc.want)
		}
		info, err := os.Stat(s.statePath())
		// Windows has no Unix modes; the supervisor only runs on Linux.
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("state is not private: %v %v", info, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPersistenceRejectsCorruptModelWithoutSilentlyResettingIt(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	seed := "persistence-validation-seed"
	baseline := initialPlant(seed, "retail", now)
	baseline.condition(1, "High temperature", true, baseline.LastTick)
	if err := validatePlant(baseline, seed, "retail", now); err != nil {
		t.Fatalf("invalid baseline: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*plant)
	}{
		{"version", func(p *plant) { p.Version++ }},
		{"profile", func(p *plant) { p.Profile = "plasma" }},
		{"seed", func(p *plant) { p.SeedFingerprint = fingerprint("different-persistence-seed") }},
		{"identity", func(p *plant) { p.Identity.Serial = "wrong" }},
		{"clock future", func(p *plant) { p.LastTick = now.Add(6 * time.Minute) }},
		{"clock zero", func(p *plant) { p.LastTick = time.Time{} }},
		{"sample clock zero", func(p *plant) { p.LastSample = time.Time{} }},
		{"sample clock future", func(p *plant) { p.LastSample = p.LastTick.Add(time.Second) }},
		{"sample clock stale", func(p *plant) { p.LastSample = p.LastTick.Add(-2 * time.Minute) }},
		{"device order", func(p *plant) { p.Devices[0], p.Devices[1] = p.Devices[1], p.Devices[0] }},
		{"device missing", func(p *plant) { p.Devices = p.Devices[:1] }},
		{"device bounds", func(p *plant) { p.Devices[0].Min = -41 }},
		{"device default", func(p *plant) { p.Devices[0].Default = 1 }},
		{"setpoint range", func(p *plant) { p.Devices[0].Setpoint = -41 }},
		{"temperature range", func(p *plant) { p.Devices[0].Temperature = 46 }},
		{"actuator consistency", func(p *plant) { p.Devices[0].Online = false; p.Devices[0].Compressor = true }},
		{"defrost missing deadline", func(p *plant) {
			p.Devices[0].Defrost = true
			p.Devices[0].Compressor = false
			p.Devices[0].DefrostUntil = time.Time{}
		}},
		{"defrost unbounded deadline", func(p *plant) {
			p.Devices[0].Defrost = true
			p.Devices[0].Compressor = false
			p.Devices[0].DefrostUntil = p.LastTick.Add(22 * time.Minute)
		}},
		{"history missing", func(p *plant) { p.History = nil }},
		{"history oversize", func(p *plant) { p.History = append(p.History, p.History[0]) }},
		{"history unknown node", func(p *plant) { p.History[0].Node = 99 }},
		{"history future", func(p *plant) { p.History[0].Time = p.LastTick.Add(time.Minute) }},
		{"history order", func(p *plant) { p.History[0].Time = p.History[len(p.History)-1].Time }},
		{"history duplicate", func(p *plant) { p.History[1] = p.History[0] }},
		{"history value", func(p *plant) { p.History[0].Setpoint = 11 }},
		{"alarm counter", func(p *plant) { p.NextAlarm = 0 }},
		{"alarm future", func(p *plant) { p.Alarms[0].Occurred = p.LastTick.Add(time.Second) }},
		{"alarm unknown node", func(p *plant) { p.Alarms[0].Node = 99 }},
		{"alarm reference", func(p *plant) { p.Alarms[0].Ref = p.NextAlarm }},
		{"alarm duplicate", func(p *plant) { p.Alarms = append(p.Alarms, p.Alarms[0]) }},
		{"alarm unbounded name", func(p *plant) { p.Alarms[0].Name = strings.Repeat("x", 101) }},
		{"active alarm cleared", func(p *plant) { p.Alarms[0].Cleared = p.LastTick }},
		{"inactive alarm without clear", func(p *plant) { p.Alarms[0].Active = false }},
		{"alarm clear before occurrence", func(p *plant) {
			p.Alarms[0].Active = false
			p.Alarms[0].Cleared = p.Alarms[0].Occurred.Add(-time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := persistenceCopy(t, baseline)
			tc.mutate(&p)
			if err := validatePlant(p, seed, "retail", now); err == nil {
				t.Fatal("corrupt stored model accepted")
			}
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			cfg := persistenceTestConfig(t.TempDir(), seed, "retail", &now)
			if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(cfg.StateDir, "state-retail.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if s, err := New(cfg); err == nil {
				s.Close()
				t.Fatal("invalid stored state silently reset or loaded")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, after) {
				t.Fatalf("invalid state was overwritten instead of retained for review: %v", err)
			}
		})
	}
	for _, corrupt := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		p := persistenceCopy(t, baseline)
		p.Devices[0].Temperature = corrupt
		if err := validatePlant(p, seed, "retail", now); err == nil {
			t.Fatal("nonfinite temperature accepted")
		}
	}
}

func TestPersistenceRejectsMalformedOversizeAndForeignSeedFiles(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	seed := "persistence-file-seed"
	valid, err := json.Marshal(initialPlant(seed, "retail", now))
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(",\"unknown\":1}")...)
	for _, tc := range []struct {
		name string
		data []byte
		seed string
	}{
		{"truncated", valid[:len(valid)/2], seed},
		{"trailing", append(append([]byte(nil), valid...), []byte(" {}")...), seed},
		{"unknown field", unknown, seed},
		{"oversize", bytes.Repeat([]byte(" "), maxStateBytes+1), seed},
		{"foreign seed", valid, "different-persistence-file-seed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := persistenceTestConfig(t.TempDir(), tc.seed, "retail", &now)
			if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(cfg.StateDir, "state-retail.json")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if s, err := New(cfg); err == nil {
				s.Close()
				t.Fatal("invalid state accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(tc.data, after) {
				t.Fatalf("invalid file was replaced: %v", err)
			}
		})
	}
}

func TestPersistencePrecommitDirectoryFailureDoesNotChangeDiskOrMemory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires unprivileged POSIX permissions")
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s, err := New(persistenceTestConfig(t.TempDir(), "persistence-atomic-seed", "retail", &now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(s.cfg.StateDir, 0o700)
		if err := s.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	before, err := os.ReadFile(s.statePath())
	if err != nil {
		t.Fatal(err)
	}
	memory := persistenceCopy(t, s.plant)
	// Write+search without read specifically exercises opening the directory
	// before rename, rather than merely failing CreateTemp in a read-only dir.
	if err := os.Chmod(s.cfg.StateDir, 0o300); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	err = s.tick()
	if err == nil || stateCommitted(err) {
		t.Fatalf("precommit failure reported as success/commit: %v", err)
	}
	if !reflect.DeepEqual(memory, s.plant) {
		t.Fatal("failed process tick changed in-memory state")
	}
	after, err := os.ReadFile(s.statePath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("precommit failure changed live state file: %v", err)
	}
	if err := os.Chmod(s.cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".state-") {
			t.Fatalf("failed transaction left staging state: %s", entry.Name())
		}
	}
	if err := s.tick(); err != nil {
		t.Fatalf("restored directory cannot persist next tick: %v", err)
	}
	if s.plant.LastTick.Equal(memory.LastTick) {
		t.Fatal("successful retry did not advance process")
	}
}

func TestPersistenceCommitUncertaintySurvivesErrorWrapping(t *testing.T) {
	cause := errors.New("directory sync unavailable")
	wrapped := fmt.Errorf("operation: %w", &committedStateError{err: cause})
	if !stateCommitted(wrapped) || !errors.Is(wrapped, cause) || stateCommitted(fmt.Errorf("before rename: %w", cause)) {
		t.Fatal("callers cannot distinguish committed-but-unconfirmed state from a precommit failure")
	}
}

func TestPersistenceRejectsMisalignedProcessClock(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	p := initialPlant("round3-clock-sequence-seed", "retail", now)
	p.LastTick = p.LastTick.Add(17 * time.Second)
	if err := validatePlant(p, "round3-clock-sequence-seed", "retail", now.Add(17*time.Second)); err != nil {
		return
	}
	p.advance(now.Add(30 * time.Second))
	t.Logf("accepted state advanced to %s for actual clock %s", p.LastTick, now.Add(30*time.Second))
	if p.LastTick.After(now.Add(30 * time.Second)) {
		t.Fatal("accepted stored tick alignment advances process/history ahead of the current clock")
	}
}

func TestPersistenceAcceptsBothFractionalClockSamplePhases(t *testing.T) {
	zone := time.FixedZone("test-offset", 5*3600+45*60)
	for _, profile := range []string{"retail", "plasma"} {
		for second := 0; second < 60; second++ {
			now := time.Date(2026, 11, 8, 12, 0, second, 239817123, zone)
			p := initialPlant("round3-fractional-clock-seed", profile, now)
			p.advance(now.Add(11*time.Minute + 17*time.Second))
			for _, clock := range []time.Time{p.LastTick, p.LastSample} {
				if !clock.Equal(clock.Truncate(30 * time.Second)) {
					t.Fatal("generated plant clock is unaligned", clock)
				}
			}
			for _, h := range p.History {
				if !h.Time.Equal(h.Time.Truncate(30 * time.Second)) {
					t.Fatal("generated history is unaligned", h.Time)
				}
			}
			p.Devices[0].Defrost = true
			p.Devices[0].Compressor = false
			p.Devices[0].DefrostUntil = now.Add(31*time.Minute + 17*time.Second)
			if err := validatePlant(p, "round3-fractional-clock-seed", profile, now.Add(11*time.Minute+17*time.Second)); err != nil {
				t.Fatalf("genuine fractional-clock/defrost state rejected: %v", err)
			}
		}
	}
}

func TestPersistenceRejectsHistoryPhaseAndIntervalCorruption(t *testing.T) {
	const seed = "retained-sample-cadence-seed"
	for _, phase := range []int{0, 30} {
		now := time.Date(2026, 11, 8, 12, 0, phase, 0, time.UTC)
		original := initialPlant(seed, "retail", now)
		if err := validatePlant(original, seed, "retail", now); err != nil {
			t.Fatalf("valid phase%d rejected: %v", phase, err)
		}
		for _, kind := range []string{"phase", "missing-interval", "missing-final-node"} {
			t.Run(fmt.Sprintf("phase%d/%s", phase, kind), func(t *testing.T) {
				p := persistenceCopy(t, original)
				switch kind {
				case "phase":
					at := p.History[30].Time
					for i := range p.History {
						if p.History[i].Time.Equal(at) {
							p.History[i].Time = p.History[i].Time.Add(30 * time.Second)
						}
					}
				case "missing-interval":
					p.History = append(p.History[:30], p.History[31:]...)
				case "missing-final-node":
					p.History = p.History[:len(p.History)-1]
				}
				if err := validatePlant(p, seed, "retail", now); err == nil {
					t.Fatalf("corrupt %s history was accepted and could be plotted at false timestamps", kind)
				}
			})
		}
	}
}

func TestPersistenceClockLagBoundariesRemainRestartable(t *testing.T) {
	const seed = "sample-clock-lag-boundary-seed"
	for _, profile := range []string{"retail", "plasma"} {
		for _, phase := range []int{0, 30} {
			for _, lag := range []time.Duration{0, 30 * time.Second, time.Minute} {
				t.Run(fmt.Sprintf("%s/phase%d/lag%s", profile, phase, lag), func(t *testing.T) {
					clock := time.Date(2026, 11, 8, 12, 0, phase, 0, time.UTC)
					p := initialPlant(seed, profile, clock)
					if lag == 0 {
						clock = clock.Add(30 * time.Second)
						p.advance(clock)
					} else if lag == time.Minute {
						// This unreachable stored boundary passes every other grid/cadence
						// check, but the next real tick would create a 90-second sample gap.
						p.LastTick = p.LastSample.Add(time.Minute)
						clock = p.LastTick
					}
					if got := p.LastTick.Sub(p.LastSample); got != lag {
						t.Fatalf("fixture lag=%s, want%s", got, lag)
					}
					cfg := persistenceTestConfig(t.TempDir(), seed, profile, &clock)
					if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(cfg.StateDir, "state-"+profile+".json")
					original, err := json.Marshal(p)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(path, original, 0600); err != nil {
						t.Fatal(err)
					}
					loaded, err := New(cfg)
					if lag == time.Minute {
						if err == nil {
							loaded.Close()
							t.Fatal("accepted unreachable exactly-one-minute sample lag")
						}
						unchanged, readErr := os.ReadFile(path)
						if readErr != nil || !bytes.Equal(unchanged, original) {
							t.Fatal("rejected sample lag silently rewrote stored state")
						}
						return
					}
					if err != nil {
						t.Fatalf("valid legacy sample phase/lag rejected: %v", err)
					}
					clock = clock.Add(30 * time.Second)
					if err = loaded.tick(); err != nil {
						t.Fatal(err)
					}
					if err = loaded.Close(); err != nil {
						t.Fatal(err)
					}
					reopened, err := New(cfg)
					if err != nil {
						t.Fatalf("accepted state became unrestartable after next tick: %v", err)
					}
					if err = reopened.Close(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
