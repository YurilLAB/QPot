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

// logRoomTopUp is how little room may be left before it is made whole
// again: a tick that finds a log has used a quarter of its room gives the
// room back.
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
}

// isLogName reports whether a file name is one the collector reads as a log
// (CollectorSources: *.log and *.json).
func isLogName(name string) bool {
	return !strings.HasPrefix(name, ".") && (strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".json"))
}
