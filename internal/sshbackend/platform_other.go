//go:build !linux && !darwin

package sshbackend

import (
	"errors"
	"io"
	"os"
	"os/exec"
)

const privateKeyReadFlags = os.O_RDONLY

func cancellableFileInput(*os.File) (io.Reader, func(), error) {
	return nil, nil, errors.New("SSH backend requires Linux")
}
func inputPipeClosed(error) bool { return false }

func execDaemon(string, []string, []string) error           { return errors.New("SSH backend requires Linux") }
func lockFile(*os.File) error                               { return errors.New("SSH backend requires Linux") }
func processSignals() []os.Signal                           { return []os.Signal{os.Interrupt} }
func setProcessGroup(*exec.Cmd, bool)                       {}
func forwardSignal(cmd *exec.Cmd, signal os.Signal, _ bool) { _ = cmd.Process.Signal(signal) }
func fileUID(os.FileInfo) int                               { return os.Getuid() }
func processExitCode(state *os.ProcessState) int            { return state.ExitCode() }
