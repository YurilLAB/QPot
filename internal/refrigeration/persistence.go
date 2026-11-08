package refrigeration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

const maxStateBytes = 2 << 20

func (s *Server) load() error {
	path := s.statePath()
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Size() > maxStateBytes {
			return errors.New("refrigeration state is not a bounded regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat refrigeration state: %w", err)
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		s.plant = initialPlant(s.cfg.DeviceSeed, s.cfg.SiteProfile, s.now())
		return s.saveLocked()
	}
	if err != nil {
		return fmt.Errorf("open refrigeration state: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat refrigeration state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxStateBytes {
		return errors.New("refrigeration state is not a bounded regular file")
	}
	dec := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	dec.DisallowUnknownFields()
	var p plant
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("decode refrigeration state: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing refrigeration state data")
	}
	if err := validatePlant(p, s.cfg.DeviceSeed, s.cfg.SiteProfile, s.now()); err != nil {
		return err
	}
	s.plant = p
	return nil
}

func validatePlant(p plant, seed, profile string, now time.Time) error {
	if p.Version != 1 || p.Profile != profile || p.SeedFingerprint != fingerprint(seed) {
		return errors.New("refrigeration state version, profile or identity does not match")
	}
	want := initialPlant(seed, profile, p.LastTick)
	if p.Identity != want.Identity || len(p.Devices) != len(want.Devices) || len(p.History) > maxHistory || len(p.Alarms) > maxAlarms || p.LastTick.IsZero() || p.NextAlarm < 1 || p.NextAlarm > 2147483647 {
		return errors.New("invalid refrigeration state identity or collection bounds")
	}
	if !p.LastTick.Equal(p.LastTick.Truncate(30*time.Second)) || p.LastTick.After(now.Add(5*time.Minute)) || p.LastSample.IsZero() || !p.LastSample.Equal(p.LastSample.Truncate(30*time.Second)) || p.LastSample.After(p.LastTick) || p.LastTick.Sub(p.LastSample) >= time.Minute {
		return errors.New("invalid refrigeration state clock")
	}
	nodes := map[int]bool{}
	deviceByNode := map[int]device{}
	for i, d := range p.Devices {
		w := want.Devices[i]
		if d.Node != w.Node || d.Name != w.Name || d.Min != w.Min || d.Max != w.Max || d.Default != w.Default || !finite(d.Temperature) || !finite(d.Setpoint) || d.Temperature < -60 || d.Temperature > 45 || d.Setpoint < d.Min || d.Setpoint > d.Max {
			return errors.New("invalid refrigeration device state")
		}
		nodes[d.Node] = true
		deviceByNode[d.Node] = d
		if d.Compressor && (!d.MainSwitch || d.Defrost || !d.Online) || d.Defrost && (!d.MainSwitch || d.DefrostUntil.IsZero() || d.DefrostUntil.After(p.LastTick.Add(21*time.Minute))) {
			return errors.New("inconsistent refrigeration actuator state")
		}
	}
	var previous time.Time
	seenSamples := map[string]bool{}
	lastByNode := map[int]time.Time{}
	for _, h := range p.History {
		d := deviceByNode[h.Node]
		key := fmt.Sprintf("%d/%d", h.Node, h.Time.UnixNano())
		if !nodes[h.Node] || h.Time.IsZero() || !h.Time.Equal(h.Time.Truncate(30*time.Second)) || !finite(h.Temperature) || !finite(h.Setpoint) || h.Temperature < -60 || h.Temperature > 45 || h.Setpoint < d.Min || h.Setpoint > d.Max || h.Time.After(p.LastSample) || !previous.IsZero() && h.Time.Before(previous) || seenSamples[key] {
			return errors.New("invalid refrigeration history")
		}
		// Either 30-second phase is valid for a minute-sampled plant. The
		// retained series must nevertheless have one phase and no missing
		// interval, since XML history encodes timestamps as start + index*rate.
		last := lastByNode[h.Node]
		if h.Time.Unix()%60 != p.LastSample.Unix()%60 || !last.IsZero() && h.Time.Sub(last) != time.Minute {
			return errors.New("inconsistent refrigeration history cadence")
		}
		lastByNode[h.Node] = h.Time
		previous = h.Time
		seenSamples[key] = true
	}
	if len(p.History) == 0 || !p.History[len(p.History)-1].Time.Equal(p.LastSample) {
		return errors.New("inconsistent refrigeration history clock")
	}
	for node := range nodes {
		if !lastByNode[node].Equal(p.LastSample) {
			return errors.New("incomplete refrigeration history sample")
		}
	}
	seen := map[int]bool{}
	for _, a := range p.Alarms {
		if !nodes[a.Node] || a.Ref < 1 || a.Ref >= p.NextAlarm || seen[a.Ref] || len(a.Name) > 100 || a.Occurred.IsZero() || a.Occurred.After(p.LastTick) || a.Active && !a.Cleared.IsZero() || !a.Active && (a.Cleared.IsZero() || a.Cleared.Before(a.Occurred) || a.Cleared.After(p.LastTick)) {
			return errors.New("invalid refrigeration alarm")
		}
		seen[a.Ref] = true
	}
	return nil
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func (s *Server) statePath() string {
	return filepath.Join(s.cfg.StateDir, "state-"+s.cfg.SiteProfile+".json")
}

func (s *Server) saveLocked() error {
	s.saves++
	data, err := json.Marshal(s.plant)
	if err != nil {
		return fmt.Errorf("encode refrigeration state: %w", err)
	}
	if len(data) > maxStateBytes {
		return errors.New("refrigeration state exceeds limit")
	}
	// Obtain the directory handle before touching the live state. A permission
	// failure here is unambiguously before the atomic rename commit point.
	dir, err := os.Open(s.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("open refrigeration state directory: %w", err)
	}
	defer dir.Close()
	f, err := os.CreateTemp(s.cfg.StateDir, ".state-*")
	if err != nil {
		return fmt.Errorf("create refrigeration state: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write refrigeration state: %w", err)
	}
	if err = os.Rename(name, s.statePath()); err != nil {
		return fmt.Errorf("replace refrigeration state: %w", err)
	}
	if err = dir.Sync(); err != nil {
		return &committedStateError{fmt.Errorf("sync committed refrigeration state directory: %w", err)}
	}
	return nil
}

// A successful rename is visible even when subsequent directory durability
// confirmation fails. Callers must never roll memory back behind that commit.
type committedStateError struct{ err error }

func (e *committedStateError) Error() string { return e.err.Error() }
func (e *committedStateError) Unwrap() error { return e.err }
func stateCommitted(err error) bool {
	var committed *committedStateError
	return errors.As(err, &committed)
}

// Close persists the latest simulated state and closes the event journal.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.plant.advance(s.now())
	err := s.saveLocked()
	if closeErr := s.events.close(); err == nil {
		err = closeErr
	}
	return err
}

func (s *Server) tick() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	old := clonePlant(s.plant)
	if s.plant.advance(s.now()) {
		err := s.saveLocked()
		if err != nil && !stateCommitted(err) {
			s.plant = old
		}
		return err
	}
	return nil
}

func (s *Server) now() time.Time { return s.cfg.Now().UTC() }
