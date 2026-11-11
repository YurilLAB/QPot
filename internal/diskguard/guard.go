// Package diskguard decides when an instance's honeypots must stop because
// the disk that holds their logs is nearly full, and when they may start
// again. A honeypot that cannot write its log still accepts connections and
// records nothing, so a honeypot that cannot record must not accept.
//
// The package only decides and remembers: Machine turns a free-space reading
// into an Action, and State is the small file that says which honeypots the
// guard itself stopped. Reading the disk, running cleanup and stopping or
// starting containers is the caller's work (internal/server).
package diskguard

import "time"

// Thresholds are the guard's two marks, in bytes. The honeypots stop below
// MinFree and start again at or above ResumeFree; between the two nothing
// changes, so a disk that hovers around one mark does not stop and start
// them in turn.
type Thresholds struct {
	// MinFree is the floor. 0 or less turns the guard off.
	MinFree int64
	// ResumeFree is the resume mark. A value below MinFree counts as
	// MinFree.
	ResumeFree int64
}

// FromMB returns the thresholds for a floor and a resume mark given in MB
// (the config's cleanup.min_free_mb and cleanup.resume_free_mb).
func FromMB(minFreeMB, resumeFreeMB int64) Thresholds {
	const maxMB = 1 << 42 // keeps the shift within int64
	return Thresholds{
		MinFree:    min(max(minFreeMB, 0), maxMB) << 20,
		ResumeFree: min(max(resumeFreeMB, 0), maxMB) << 20,
	}
}

// On reports whether the guard is on.
func (t Thresholds) On() bool { return t.MinFree > 0 }

// resume is the resume mark, never below the floor.
func (t Thresholds) resume() int64 { return max(t.ResumeFree, t.MinFree) }

// Reading is one look at the disk.
type Reading struct {
	// Free is the free space in bytes.
	Free int64
	// Known is false when the free space could not be read. The guard then
	// does nothing: it neither stops nor starts a honeypot on a guess. A
	// full disk is Free 0 with Known true.
	Known bool
}

// Action is what the caller does after a reading.
type Action int

const (
	// None: leave everything as it is.
	None Action = iota
	// Cleanup: the disk is below the floor and cleanup has not been tried
	// lately. Run it, read the disk again and ask Next once more.
	Cleanup
	// Stop: the disk is below the floor. Stop every honeypot that runs.
	Stop
	// Resume: there is room again (or the guard was turned off). Start the
	// honeypots the guard stopped.
	Resume
)

// String names the action for logs and tests.
func (a Action) String() string {
	switch a {
	case None:
		return "none"
	case Cleanup:
		return "cleanup"
	case Stop:
		return "stop"
	case Resume:
		return "resume"
	}
	return "unknown"
}

// CleanupRetry is how long the guard waits before it asks for another
// cleanup while the disk stays below the floor.
const CleanupRetry = 10 * time.Minute

// Machine is the guard's state machine. It keeps one thing between
// readings: when it last asked for a cleanup in the current low spell. The
// zero Machine is ready to use; it is not safe for concurrent use.
type Machine struct {
	cleanedAt time.Time
}

// Next returns what to do after a reading. held says whether the guard
// still holds honeypots it stopped (the State lists some).
//
// Below the floor it first asks for a Cleanup, once per CleanupRetry; the
// caller runs it, reads the disk again and calls Next again, which then
// answers Stop if the disk is still below the floor. Stop is answered on
// every later reading below the floor too, so a honeypot that was started
// again meanwhile is stopped again. At or above the resume mark it answers
// Resume while honeypots are held. Between the marks, and when the free
// space is unknown, it answers None.
func (m *Machine) Next(now time.Time, t Thresholds, r Reading, held bool) Action {
	if !t.On() {
		// Turned off: give back what the guard holds.
		m.cleanedAt = time.Time{}
		if held {
			return Resume
		}
		return None
	}
	if !r.Known {
		return None
	}
	switch {
	case r.Free >= t.resume():
		// The low spell is over: the next one starts with a cleanup.
		m.cleanedAt = time.Time{}
		if held {
			return Resume
		}
		return None
	case r.Free >= t.MinFree:
		return None
	}
	if m.cleanedAt.IsZero() || now.Sub(m.cleanedAt) >= CleanupRetry || now.Before(m.cleanedAt) {
		m.cleanedAt = now
		return Cleanup
	}
	return Stop
}

// Condition is what a status line says about the guard.
type Condition string

const (
	// Off: the guard is turned off (min_free_mb: 0).
	Off Condition = "off"
	// Unknown: the free space could not be read.
	Unknown Condition = "unknown"
	// OK: there is room and the guard holds nothing.
	OK Condition = "ok"
	// Low: the disk is below the floor; the guard keeps the honeypots
	// stopped.
	Low Condition = "low"
	// Waiting: the disk is at or above the floor, and honeypots the guard
	// stopped are not running again yet (they start at the resume mark).
	Waiting Condition = "waiting"
)

// Describe returns the guard's condition for a reading. held is as for
// Machine.Next.
func Describe(t Thresholds, r Reading, held bool) Condition {
	switch {
	case !t.On():
		return Off
	case !r.Known:
		return Unknown
	case r.Free < t.MinFree:
		return Low
	case held:
		return Waiting
	}
	return OK
}
