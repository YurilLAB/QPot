package diskguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// StateFile is the name of the guard's state file in the instance's data
// folder.
const StateFile = "disk-guard.json"

const (
	// stateVersion is the only file format there is.
	stateVersion = 1
	// maxStateBytes bounds a state file read: MaxStopped entries are well
	// below it.
	maxStateBytes = 64 << 10
)

// MaxStopped bounds the honeypots a state lists (an instance has a few
// dozen at most).
const MaxStopped = 256

// namePattern is a honeypot name as the instance config accepts it.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Stopped is one honeypot the guard stopped.
type Stopped struct {
	Name      string    `json:"name"`
	StoppedAt time.Time `json:"stopped_at"`
}

// State lists the honeypots the guard itself stopped and has not started
// again, by name. Only these are started when there is room again: a
// honeypot the operator stopped or turned off is never in it. The zero
// State lists none.
type State struct {
	Stopped []Stopped
}

// stateJSON is the file's layout.
type stateJSON struct {
	Version int       `json:"version"`
	Stopped []Stopped `json:"stopped"`
}

// Path returns the state file of the instance whose data folder is dataPath.
func Path(dataPath string) string { return filepath.Join(dataPath, StateFile) }

// Held reports whether the state lists any honeypot.
func (s State) Held() bool { return len(s.Stopped) > 0 }

// Has reports whether the state lists the honeypot.
func (s State) Has(name string) bool {
	for _, e := range s.Stopped {
		if e.Name == name {
			return true
		}
	}
	return false
}

// Names returns the listed honeypots, by name.
func (s State) Names() []string {
	out := make([]string, 0, len(s.Stopped))
	for _, e := range s.Stopped {
		out = append(out, e.Name)
	}
	return out
}

// Add lists a honeypot as stopped at the given time and reports whether the
// state changed. A honeypot already listed keeps its first time. A name that
// is not a honeypot name, or one more than MaxStopped, is not added.
func (s *State) Add(name string, at time.Time) bool {
	if !namePattern.MatchString(name) || s.Has(name) || len(s.Stopped) >= MaxStopped {
		return false
	}
	s.Stopped = append(s.Stopped, Stopped{Name: name, StoppedAt: at.UTC().Truncate(time.Second)})
	sort.Slice(s.Stopped, func(i, j int) bool { return s.Stopped[i].Name < s.Stopped[j].Name })
	return true
}

// Remove takes a honeypot off the list and reports whether it was on it.
func (s *State) Remove(name string) bool {
	for i, e := range s.Stopped {
		if e.Name == name {
			s.Stopped = append(s.Stopped[:i:i], s.Stopped[i+1:]...)
			return true
		}
	}
	return false
}

// Clone returns a copy that shares nothing with s.
func (s State) Clone() State {
	return State{Stopped: append([]Stopped(nil), s.Stopped...)}
}

// Marshal renders the state as the state file's contents.
func (s State) Marshal() ([]byte, error) {
	stopped := s.Stopped
	if stopped == nil {
		stopped = []Stopped{}
	}
	data, err := json.MarshalIndent(stateJSON{Version: stateVersion, Stopped: stopped}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseState reads a state file's contents. Anything it does not fully
// understand is an error: another version, an unknown field, a name that is
// not a honeypot name, a name listed twice, more than MaxStopped entries or
// data after the object. The caller then treats the guard as having stopped
// nothing, so a damaged file never starts a honeypot.
func ParseState(data []byte) (State, error) {
	if len(data) > maxStateBytes {
		return State{}, fmt.Errorf("disk guard state is larger than %d bytes", maxStateBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw stateJSON
	if err := dec.Decode(&raw); err != nil {
		return State{}, fmt.Errorf("disk guard state is not valid: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return State{}, errors.New("disk guard state has data after its end")
	}
	if raw.Version != stateVersion {
		return State{}, fmt.Errorf("disk guard state has version %d, not %d", raw.Version, stateVersion)
	}
	if len(raw.Stopped) > MaxStopped {
		return State{}, fmt.Errorf("disk guard state lists more than %d honeypots", MaxStopped)
	}
	var s State
	for _, e := range raw.Stopped {
		if !namePattern.MatchString(e.Name) {
			return State{}, errors.New("disk guard state lists a name that is not a honeypot name")
		}
		if s.Has(e.Name) {
			return State{}, fmt.Errorf("disk guard state lists %s twice", e.Name)
		}
		at := e.StoppedAt.UTC()
		// A time zone can push a year out of what JSON carries; such a
		// time could be read and never written again.
		if y := at.Year(); y < 0 || y > 9999 {
			return State{}, errors.New("disk guard state has a time out of range")
		}
		s.Stopped = append(s.Stopped, Stopped{Name: e.Name, StoppedAt: at})
	}
	sort.Slice(s.Stopped, func(i, j int) bool { return s.Stopped[i].Name < s.Stopped[j].Name })
	return s, nil
}

// LoadState reads the state file at path. A missing file is the zero State
// and no error. A file that cannot be read or understood is the zero State
// and an error: the guard stopped nothing as far as anyone can tell.
func LoadState(path string) (State, error) {
	data, err := config.ReadFile(path, maxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read disk guard state: %w", err)
	}
	return ParseState(data)
}

// SaveState writes the state to path so that a reader sees the old file or
// the new one, never a part of either. A State that lists nothing removes
// the file, which needs no free space.
func SaveState(path string, s State) error {
	if !s.Held() {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove disk guard state: %w", err)
		}
		return nil
	}
	data, err := s.Marshal()
	if err != nil {
		return fmt.Errorf("encode disk guard state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".disk-guard-*.tmp")
	if err != nil {
		return fmt.Errorf("write disk guard state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write disk guard state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write disk guard state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write disk guard state: %w", err)
	}
	if err := config.ReplaceFile(tmp.Name(), path); err != nil {
		return fmt.Errorf("write disk guard state: %w", err)
	}
	return nil
}
