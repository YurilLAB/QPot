package behaviour

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// stateFile is the state's file in an instance's data folder.
const stateFile = "behaviour.json"

// maxStateBytes bounds the state file read back.
const maxStateBytes = 64 << 20

// StatePath returns the state file of an instance's data folder.
func StatePath(dataPath string) string { return filepath.Join(dataPath, stateFile) }

// Load reads the state of an instance. A missing file is a state that has
// not run. A file that cannot be read as a state is an error: starting over
// silently would take a new baseline and hide what happened meanwhile.
func Load(dataPath string) (*State, error) {
	f, err := os.Open(StatePath(dataPath))
	if errors.Is(err, fs.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("behaviour: read state: %w", err)
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() > maxStateBytes {
		return nil, fmt.Errorf("behaviour: state file %s is not usable (larger than %d bytes, or unreadable)", stateFile, maxStateBytes)
	}
	var s State
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, fmt.Errorf("behaviour: parse state: %w", err)
	}
	if s.Version > 1 {
		return nil, fmt.Errorf("behaviour: state file is of version %d, written by a newer QPot", s.Version)
	}
	if len(s.Alerts) > MaxAlerts {
		s.Alerts = s.Alerts[len(s.Alerts)-MaxAlerts:]
	}
	s.init()
	return &s, nil
}

// Save writes the state so that a crash leaves either the old file or the
// new one, never part of one.
func Save(dataPath string, s *State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("behaviour: encode state: %w", err)
	}
	tmp, err := os.CreateTemp(dataPath, stateFile+".*.tmp")
	if err != nil {
		return fmt.Errorf("behaviour: write state: %w", err)
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o600)
	}
	if err == nil {
		err = os.Rename(name, StatePath(dataPath))
	}
	if err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("behaviour: write state: %w", err)
	}
	return nil
}
