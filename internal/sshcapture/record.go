// Package sshcapture turns the session capture that the HiFi backend's
// OpenSSH writes to its container output into the per-command evidence files
// the collector reads. The capture never touches the guest's filesystem; the
// trusted control plane reads it from Docker's log stream.
package sshcapture

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxLine is the longest capture line: one atomic pipe write (PIPE_BUF).
const MaxLine = 4096

// maxPayload is the longest decoded payload of one record.
const maxPayload = 2048

// Kind is the type of one capture record.
type Kind byte

// Record kinds, as written by the backend's sshd.
const (
	KindCommand          Kind = 'c' // a chunk of the exec command, before Open
	KindCommandTruncated Kind = 'C' // the command was longer than captured
	KindOpen             Kind = 'o' // session metadata
	KindInput            Kind = 'i' // bytes written to the session
	KindOutput           Kind = 'O' // bytes the session printed
	KindError            Kind = 'e' // bytes the session printed to stderr
	KindTruncated        Kind = 't' // the capture budget ran out
	KindExit             Kind = 'x' // exit status or signal
	KindClosed           Kind = 'z' // channel freed, after its last data
)

// Record is one parsed capture line.
type Record struct {
	Conn    string // 32 lowercase hex characters, one per SSH connection
	Channel int
	Seq     uint64
	Kind    Kind
	Millis  int64 // since the channel started
	Payload []byte
}

var errRecord = errors.New("not a session capture record")

// ParseRecord parses one capture line, without its trailing newline. Anything
// that is not exactly a record is rejected: the stream is the container's
// standard output, which only the backend's sshd writes.
func ParseRecord(line []byte) (Record, error) {
	var r Record
	if len(line) > MaxLine {
		return r, errRecord
	}
	fields := bytes.Split(line, []byte{' '})
	if len(fields) != 6 {
		return r, errRecord
	}
	conn := string(fields[0])
	if len(conn) != 32 || strings.Trim(conn, "0123456789abcdef") != "" {
		return r, errRecord
	}
	channel, err := decimal(fields[1], 1<<20)
	if err != nil {
		return r, errRecord
	}
	seq, err := decimal(fields[2], 1<<62)
	if err != nil {
		return r, errRecord
	}
	if len(fields[3]) != 1 {
		return r, errRecord
	}
	kind := Kind(fields[3][0])
	switch kind {
	case KindCommand, KindCommandTruncated, KindOpen, KindInput, KindOutput,
		KindError, KindTruncated, KindExit, KindClosed:
	default:
		return r, errRecord
	}
	millis, err := decimal(fields[4], 1<<53)
	if err != nil {
		return r, errRecord
	}
	// The decoder skips CR and LF even in strict mode: allow only the alphabet.
	if bytes.IndexFunc(fields[5], func(c rune) bool {
		return !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=')
	}) >= 0 {
		return r, errRecord
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(string(fields[5]))
	if err != nil || len(payload) > maxPayload {
		return r, errRecord
	}
	switch kind {
	case KindCommandTruncated, KindTruncated, KindClosed:
		if len(payload) != 0 {
			return r, errRecord
		}
	case KindCommand, KindOpen, KindExit, KindInput, KindOutput, KindError:
		if len(payload) == 0 {
			return r, errRecord
		}
	}
	return Record{Conn: conn, Channel: int(channel), Seq: seq, Kind: kind, Millis: int64(millis), Payload: payload}, nil
}

// decimal parses a plain non-negative decimal no larger than limit.
func decimal(field []byte, limit uint64) (uint64, error) {
	if len(field) == 0 || len(field) > 20 || (len(field) > 1 && field[0] == '0') {
		return 0, errRecord
	}
	for _, c := range field {
		if c < '0' || c > '9' {
			return 0, errRecord
		}
	}
	v, err := strconv.ParseUint(string(field), 10, 64)
	if err != nil || v > limit {
		return 0, errRecord
	}
	return v, nil
}

// Open is the metadata of a session's open record.
type Open struct {
	TimeMillis int64
	UID        int
	PTY        bool
	Subsystem  bool
	HasCommand bool
	PeerPort   int // the address the backend saw: the broker's dial port
	LocalPort  int
	PeerIP     string
	Hostname   string
	Username   string
}

// ParseOpen parses an open record's payload.
func ParseOpen(payload []byte) (Open, error) {
	var o Open
	text := string(payload)
	// user is last and the only value that may hold anything but a token.
	head, user, ok := strings.Cut(text, " user=")
	if !ok || user == "" || strings.ContainsAny(user, " \n\r\t\x00") {
		return o, fmt.Errorf("open record: bad user")
	}
	o.Username = user
	seen := map[string]bool{}
	for _, field := range strings.Split(head, " ") {
		key, value, ok := strings.Cut(field, "=")
		if !ok || seen[key] {
			return o, fmt.Errorf("open record: bad field %q", field)
		}
		seen[key] = true
		var err error
		switch key {
		case "time":
			var v uint64
			v, err = decimal([]byte(value), 1<<53)
			o.TimeMillis = int64(v)
		case "uid":
			var v uint64
			v, err = decimal([]byte(value), 1<<32-1)
			o.UID = int(v)
		case "pty", "sub", "cmd":
			if value != "0" && value != "1" {
				err = errRecord
			}
			switch key {
			case "pty":
				o.PTY = value == "1"
			case "sub":
				o.Subsystem = value == "1"
			default:
				o.HasCommand = value == "1"
			}
		case "rport", "lport":
			var v uint64
			v, err = decimal([]byte(value), 65535)
			if key == "rport" {
				o.PeerPort = int(v)
			} else {
				o.LocalPort = int(v)
			}
		case "rip":
			if value == "" || len(value) > 64 {
				err = errRecord
			}
			o.PeerIP = value
		case "host":
			if len(value) > 255 {
				err = errRecord
			}
			o.Hostname = value
		default:
			err = errRecord
		}
		if err != nil {
			return o, fmt.Errorf("open record: bad %s", key)
		}
	}
	for _, key := range []string{"time", "uid", "pty", "sub", "cmd", "rport", "lport", "rip", "host"} {
		if !seen[key] {
			return o, fmt.Errorf("open record: missing %s", key)
		}
	}
	return o, nil
}

// Exit is a session's exit: a code, or the signal that ended it.
type Exit struct {
	Code   int
	Signal int // 0 when the session exited normally
}

// ParseExit parses an exit record's payload.
func ParseExit(payload []byte) (Exit, error) {
	key, value, ok := strings.Cut(string(payload), "=")
	if !ok {
		return Exit{}, errRecord
	}
	v, err := decimal([]byte(value), 255)
	if err != nil {
		return Exit{}, errRecord
	}
	switch key {
	case "exit":
		return Exit{Code: int(v)}, nil
	case "signal":
		if v == 0 {
			return Exit{}, errRecord
		}
		return Exit{Code: 128 + int(v), Signal: int(v)}, nil
	}
	return Exit{}, errRecord
}
