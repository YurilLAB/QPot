//go:build windows

package server

import "os/exec"

// configureHookProcessGroup is a no-op on Windows: exec.CommandContext's default
// cancellation (Process.Kill) is used, and the WaitDelay backstop set by the
// caller ensures Wait still returns even if a descendant holds the output pipe.
// Full process-tree teardown would require a Job object, which is out of scope.
func configureHookProcessGroup(cmd *exec.Cmd) {}
