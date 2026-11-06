package hostsetup

import (
	"strings"
)

// StepKind tells ClassifyFailure what a failed command was doing, which
// decides the code when its output names no specific cause.
type StepKind int

const (
	KindOther   StepKind = iota
	KindUpdate           // refreshing package lists
	KindInstall          // installing or upgrading packages
	KindRemove           // removing conflicting packages
	KindService          // starting or enabling a service
	KindFile             // placing a key or a source file
	KindDesktop          // Docker Desktop installer (brew, winget)
	KindGroup            // adding the user to the docker group
)

// failurePattern maps text a command prints to an error code. Patterns are
// matched lower-case and in order: the first match wins.
type failurePattern struct {
	code  string
	why   string
	words []string
}

var failurePatterns = []failurePattern{
	{"QP-PERM-002", "sudo asked for a password, but setup has no terminal to type it in.",
		[]string{"a password is required", "a terminal is required", "no tty present"}},
	{"QP-PERM-003", "sudo does not allow your user to run this command.",
		[]string{"is not in the sudoers file", "not allowed to execute", "incorrect password attempt", "may not run sudo"}},
	{"QP-PKG-005", "A previous software installation stopped half-way.",
		[]string{"dpkg was interrupted", "you must manually run 'sudo dpkg --configure -a'", "dpkg --configure -a"}},
	{"QP-PKG-001", "Another program holds the package manager's lock.",
		[]string{"could not get lock", "unable to lock", "unable to acquire the dpkg", "is another process using it",
			"waiting for cache lock", "waiting for process with pid", "system management is locked",
			"unable to lock database", "failed to init transaction (unable to lock", "db.lck", "rpmdb: lock",
			"another app is currently holding the yum lock"}},
	{"QP-RES-004", "The disk is full.",
		[]string{"no space left on device", "you don't have enough free space", "not enough free space",
			"disk requirements", "insufficient space"}},
	{"QP-PKG-002", "The computer's clock is behind, so the package lists look like they come from the future.",
		[]string{"is not valid yet", "not valid yet"}},
	{"QP-PKG-003", "A package source's signing key could not be checked.",
		[]string{"no_pubkey", "signatures couldn't be verified", "is not signed", "gpg error", "signature verification failed",
			"public key for", "gpg check failed", "invalid signature", "badsig", "signature is invalid", "openpgp signature"}},
	{"QP-NET-006", "The package manager could not look up the download server's name (no internet, or DNS is not working).",
		[]string{"temporary failure resolving", "could not resolve", "name or service not known", "failed to resolve",
			"no address associated", "temporary failure in name resolution"}},
	{"QP-NET-006", "The package manager could not reach the download server.",
		[]string{"failed to fetch", "cannot download", "curl error", "failed to download", "connection timed out",
			"could not connect", "network is unreachable", "connection refused", "unable to connect",
			"failed to retrieve", "download failed", "cannot find a valid baseurl", "failed to synchronize",
			"errors during downloading metadata", "valid metadata file"}},
	{"QP-PKG-006", "Packages are installed that conflict with Docker's packages.",
		[]string{"conflicts with", "conflicting requests", "breaks:", " conflicts:", "but it is not going to be installed",
			"held broken packages", "are in conflict"}},
	{"QP-PKG-007", "The package manager does not know one of the packages.",
		[]string{"unable to locate package", "has no installation candidate", "no match for argument",
			"nothing provides", "target not found", "not found in package names", "no provider of",
			"no package", "package not found"}},
}

// ClassifyFailure turns a failed command into a coded error with plain
// words, keeping the command, its exit status and its last output lines as
// the details.
func ClassifyFailure(kind StepKind, cmdline string, res Result) *Error {
	details := "command: " + cmdline + "\nexit status: " + itoaSigned(res.Exit)
	if out := LastLines(res.Combined(), 12); out != "" {
		details += "\noutput:\n" + out
	}
	switch {
	case res.Canceled:
		return E("QP-INT-001").WithDetails("%s", details)
	case res.TimedOut:
		if kind == KindUpdate || kind == KindInstall || kind == KindRemove {
			return E("QP-PKG-009").WithDetails("%s", details)
		}
		return E("QP-INT-002").WithDetails("%s", details)
	case res.Err != nil && res.Exit < 0:
		// The program did not start at all.
		return E("QP-HOST-009").WithWhy("The command %q could not be started: it is not installed or not on the PATH.",
			firstWord(cmdline)).WithDetails("%s\nerror: %v", details, res.Err)
	}
	text := strings.ToLower(res.Combined())
	for _, p := range failurePatterns {
		for _, w := range p.words {
			if strings.Contains(text, w) {
				return E(p.code).WithWhy("%s", p.why).WithDetails("%s", details)
			}
		}
	}
	switch kind {
	case KindUpdate:
		return E("QP-PKG-002").WithDetails("%s", details)
	case KindInstall, KindRemove:
		return E("QP-PKG-004").WithDetails("%s", details)
	case KindService:
		return E("QP-DOCKER-003").WithDetails("%s", details)
	case KindDesktop:
		return E("QP-DOCKER-009").WithDetails("%s", details)
	case KindFile:
		return E("QP-PERM-008").WithDetails("%s", details)
	case KindGroup:
		return E("QP-PERM-009").WithDetails("%s", details)
	}
	return E("QP-BUG-001").WithWhy("A command failed in a way setup does not recognise.").WithDetails("%s", details)
}

func itoaSigned(n int) string {
	if n < 0 {
		return "none (it did not finish)"
	}
	s := ""
	for {
		s = string(rune('0'+n%10)) + s
		n /= 10
		if n == 0 {
			return s
		}
	}
}

func firstWord(s string) string {
	f := strings.Fields(s)
	for i, w := range f {
		if w == "sudo" || w == "-n" || w == "env" || strings.Contains(w, "=") {
			continue
		}
		return f[i]
	}
	return s
}
