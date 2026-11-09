package sshcapture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// connectEvent is the broker's record of one connection it handed to a cell,
// written before the first byte reaches the backend.
type connectEvent struct {
	Timestamp   string  `json:"timestamp"`
	EventType   string  `json:"event_type"`
	SrcIP       string  `json:"src_ip"`
	SrcPort     int     `json:"src_port"`
	Backend     string  `json:"backend"`
	SessionID   string  `json:"session_id"`
	Generation  *uint64 `json:"generation"`
	BackendPort int     `json:"backend_port"`
}

// EventConnect is the broker event type the index reads.
const EventConnect = "ssh_proxy_connect"

const maxConnectsPerBackend = 4096

type connect struct {
	at          time.Time
	backendPort int
	attribution Attribution
}

// BrokerIndex follows the broker's session log and answers which visitor
// connection reached a backend.
type BrokerIndex struct {
	path string

	mu       sync.Mutex
	offset   int64
	identity os.FileInfo
	partial  []byte
	byCell   map[string][]connect
}

// NewBrokerIndex reads the broker log at path.
func NewBrokerIndex(path string) *BrokerIndex {
	return &BrokerIndex{path: path, byCell: map[string][]connect{}}
}

// Attributor answers for sessions on the given cell's service. The cell's app
// matches the exact broker connection by the port the broker dialed from.
// Its backup host is reached from inside the cell, so a backup session names
// a connection only when that one alone had reached the cell: with more, any
// of them, or a process one left running, may have made it, and it names the
// visitor instead (the address of its latest connection, and the lease).
// Only connections made after the container's creation count: one container
// serves one lease, so a record forged inside it names no earlier visitor.
func (x *BrokerIndex) Attributor(cell string, app bool) Attributor {
	return func(o Open, since time.Time) (Attribution, bool) {
		at := time.UnixMilli(o.TimeMillis)
		if app {
			if a, ok := x.lookup(cell, true, o.PeerPort, at, since); ok {
				return a, true
			}
		}
		// A backup session is judged against every connection before it.
		x.refresh()
		return x.lookup(cell, app, o.PeerPort, at, since)
	}
}

func (x *BrokerIndex) lookup(cell string, app bool, port int, at, since time.Time) (Attribution, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	var best *connect
	reached := 0
	for i := range x.byCell[cell] {
		c := &x.byCell[cell][i]
		// The connect line is written before the dial completes, so it is
		// never later than the session; allow for clock granularity only.
		if c.at.Before(since) || c.at.After(at.Add(time.Second)) || (app && c.backendPort != port) {
			continue
		}
		reached++
		if best == nil || c.at.After(best.at) {
			best = c
		}
	}
	if best == nil {
		return Attribution{}, false
	}
	if app || reached == 1 {
		return best.attribution, true
	}
	return Attribution{SrcIP: best.attribution.SrcIP, Generation: best.attribution.Generation, Visitor: true}, true
}

// refresh reads what the broker appended since the last read. A replaced or
// shortened log is read from its start.
func (x *BrokerIndex) refresh() {
	x.mu.Lock()
	defer x.mu.Unlock()
	f, err := os.Open(x.path)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if x.identity == nil || !os.SameFile(x.identity, info) || info.Size() < x.offset {
		x.offset, x.partial = 0, nil
	}
	x.identity = info
	if _, err := f.Seek(x.offset, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadSlice('\n')
		x.offset += int64(len(line))
		if errors.Is(err, bufio.ErrBufferFull) {
			x.partial = nil // longer than any broker event: skip it
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = r.ReadSlice('\n')
				x.offset += int64(len(line))
			}
			continue
		}
		if err != nil {
			x.partial = append(x.partial, line...)
			return
		}
		full := append(x.partial, line...)
		x.partial = nil
		x.add(bytes.TrimSpace(full))
	}
}

func (x *BrokerIndex) add(line []byte) {
	if !bytes.Contains(line, []byte(EventConnect)) {
		return
	}
	var ev connectEvent
	if json.Unmarshal(line, &ev) != nil || ev.EventType != EventConnect || ev.Backend == "" ||
		ev.BackendPort < 1 || ev.BackendPort > 65535 || ev.SrcIP == "" || strings.ContainsAny(ev.Backend, "/\\") {
		return
	}
	at, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
	if err != nil {
		return
	}
	list := append(x.byCell[ev.Backend], connect{at: at, backendPort: ev.BackendPort,
		attribution: Attribution{SrcIP: ev.SrcIP, SrcPort: ev.SrcPort, SessionID: ev.SessionID, Generation: ev.Generation}})
	if len(list) > maxConnectsPerBackend {
		list = append([]connect(nil), list[len(list)-maxConnectsPerBackend:]...)
	}
	x.byCell[ev.Backend] = list
}
