package cicheck

import (
	"os/exec"
	"time"
)

// killGroup kills the command when its context ends. (scripts/ci-local.sh
// runs on Linux; on Windows only the tests use the runner.)
func killGroup(cmd *exec.Cmd) { cmd.WaitDelay = 10 * time.Second }
