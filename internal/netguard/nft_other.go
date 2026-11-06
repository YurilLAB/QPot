//go:build !linux

package netguard

import "errors"

// errNotLinux: nftables exists only on Linux. The guard runs in a container on
// the docker host (on Docker Desktop, its Linux VM), never on another OS.
var errNotLinux = errors.New("netguard: nftables needs Linux")

// Apply is only available on Linux.
func Apply(Spec) error { return errNotLinux }

// Check is only available on Linux.
func Check(Spec) error { return errNotLinux }

// Remove is only available on Linux.
func Remove(string) error { return errNotLinux }
