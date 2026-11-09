package instance

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCowrieVirtualUserState verifies actions followed by independent identity
// queries, filesystem observations, and failed-transaction snapshots. The
// stateful image acceptance test repeats core transitions on the pinned VFS.
func TestCowrieVirtualUserState(t *testing.T) {
	cmd := exec.Command(python(t), "-I", filepath.Join("testdata", "cowrie_users.py"),
		filepath.Join("honeypotfiles", "cowrie", "adduser.py"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("virtual user transitions: %v\n%s", err, out)
	}
	var result struct {
		Count  int    `json:"count"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(out, &result); err != nil || result.Result != "PASS" || result.Count == 0 {
		t.Fatalf("account transition results: %v %s", err, out)
	}
}
