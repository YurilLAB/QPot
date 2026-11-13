package diskguard

import (
	"errors"
	"strings"
)

// LogRoom is the space kept allocated beyond the end of every honeypot log,
// in bytes.
//
// A disk can go from enough to nothing between two looks of the guard, and
// then a honeypot's next log write fails: the image's own code drops the
// event, writes part of the line, or (Conpot) stops. Space a file already
// holds beyond its end (fallocate with FALLOC_FL_KEEP_SIZE) needs no new
// blocks, so writes into it succeed on a full disk: each honeypot can go on
// logging this much, unchanged, until the guard has stopped it. The file's
// size does not change, so the collector and cleanup see the log as it is.
// Measured on ext4 and tmpfs filled to the last byte: about a megabyte of
// lines written into the room, nothing written without it.
const LogRoom = 1 << 20

// LogRoomFiles is the most logs of one honeypot that have room at a time.
//
// The folder is the container's, and room is space on the host: without a
// bound, a compromised honeypot that creates thousands of empty logs would
// make QPot reserve a megabyte for each. The honeypots write at most two
// logs each that the collector reads (Conpot conpot.json and conpot.log,
// ADBHoney adbhoney.json and adbhoney.log; Cowrie, endlessh, Dionaea and
// Heralding one), counted from their configurations and from the logs
// measured on their images. Four leave room for a release that adds one
// without letting a folder take more than four megabytes. Every log that
// has room now counts, whatever its name, so the
// bound holds across ticks: a slot comes free only when a honeypot has
// written its room full with lines of its own.
const LogRoomFiles = 4

// LogRoomEntries is the most entries a logs folder may hold for its logs to
// get room. Which logs have room is told from the folder's listing, every
// tick; a honeypot keeps a few logs and their rotated files there, and a
// folder past this many is one its container filled. Its logs get no new
// room: reading it all, every few seconds, would be the host's time the
// container spends.
const LogRoomEntries = 4096

// LogRoomOptions say which logs of a folder get room first, how many may
// have it, and whether the disk can spare more.
type LogRoomOptions struct {
	// Preferred are the honeypot's own logs (its deploy profile's): they
	// get room first, in this order; the folder's other logs follow in name
	// order.
	Preferred []string
	// MaxFiles is the most logs with room at a time (LogRoomFiles when 0).
	MaxFiles int
	// Allow is asked before each allocation and says whether the disk can
	// spare LogRoom now (nil allows).
	Allow func() bool
}

// logRoomTopUp is how much room counts as whole when the disk cannot spare
// more: a log that still has three quarters of its room is not reported
// then. While the disk can spare it, the room is made whole on every call.
const logRoomTopUp = LogRoom * 3 / 4

// ErrLogRoomUnsupported: this system cannot keep room beyond a file's end
// (not Linux).
var ErrLogRoomUnsupported = errors.New("keeping room beyond a log's end needs Linux")

// LogRoomResult is what KeepLogRoom did in one folder.
type LogRoomResult struct {
	// Kept are the logs that have their room now.
	Kept []string
	// Denied are the logs QPot may not write to: a honeypot created them
	// as its own user. They get no room.
	Denied []string
	// Failed are the logs whose room could not be kept for another reason
	// (the disk is full, the filesystem cannot), with the error.
	Failed map[string]error
	// Over are the logs that get no room because LogRoomFiles of the
	// folder's logs have it already.
	Over []string
	// Crowded says the folder holds more than LogRoomEntries entries:
	// nothing in it was given room.
	Crowded bool
	// Held is how many logs of the folder have room after the call.
	Held int
}

// isLogName reports whether a file name is one the collector reads as a log
// (CollectorSources: *.log and *.json).
func isLogName(name string) bool {
	return !strings.HasPrefix(name, ".") && (strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".json"))
}
