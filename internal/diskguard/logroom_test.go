package diskguard

import (
	"errors"
	"runtime"
	"testing"
)

// TestKeepLogRoomOffLinux: elsewhere the guard keeps no room and says why.
// (The Linux behaviour is tested with real files in internal/instance.)
func TestKeepLogRoomOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux keeps room")
	}
	if _, err := KeepLogRoom(t.TempDir()); !errors.Is(err, ErrLogRoomUnsupported) {
		t.Fatalf("KeepLogRoom: %v", err)
	}
}

// TestIsLogName: room goes to the files the collector reads as logs.
func TestIsLogName(t *testing.T) {
	for name, want := range map[string]bool{"cowrie.json": true, "conpot.log": true, "endlessh.log": true,
		"x.txt": false, ".hidden.json": false, "cowrie.json.1": false, "log": false} {
		if isLogName(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}
