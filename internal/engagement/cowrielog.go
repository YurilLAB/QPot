package engagement

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// MaxLogLine is the longest Cowrie log line read. A longer line is skipped
// and counted, without being held in memory.
const MaxLogLine = 1 << 20

// CowrieHoneypot is the honeypot name given to events read from a Cowrie log.
const CowrieHoneypot = "cowrie"

// LogStats counts the lines of a log file and what became of them.
// Lines = Events + Malformed + Oversized + Blank.
type LogStats struct {
	Lines int64 `json:"lines"`
	// Events are the lines that became an event.
	Events int64 `json:"events"`
	// Malformed are not a JSON object, or lack an eventid or a readable
	// timestamp.
	Malformed int64 `json:"malformed"`
	// Oversized are longer than MaxLogLine.
	Oversized int64 `json:"oversized"`
	Blank     int64 `json:"blank"`
	// OutsideWindow is set by a caller that drops events outside a time
	// window; ReadCowrieLog leaves it zero.
	OutsideWindow int64 `json:"outside_window"`
}

// looseString takes a JSON string and ignores any other type, so one odd
// field does not cost the whole line.
type looseString string

func (s *looseString) UnmarshalJSON(b []byte) error {
	var v string
	if json.Unmarshal(b, &v) == nil {
		*s = looseString(v)
	}
	return nil
}

// looseSeconds takes a JSON number or a string holding one.
type looseSeconds float64

func (s *looseSeconds) UnmarshalJSON(b []byte) error {
	text := strings.Trim(string(b), `"`)
	if v, err := strconv.ParseFloat(text, 64); err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
		*s = looseSeconds(v)
	}
	return nil
}

// cowrieLine is the part of a Cowrie JSON log line the metrics use.
type cowrieLine struct {
	EventID   looseString  `json:"eventid"`
	Timestamp looseString  `json:"timestamp"`
	SrcIP     looseString  `json:"src_ip"`
	Session   looseString  `json:"session"`
	Username  looseString  `json:"username"`
	Password  looseString  `json:"password"`
	Input     looseString  `json:"input"`
	URL       looseString  `json:"url"`
	Shasum    looseString  `json:"shasum"`
	Duration  looseSeconds `json:"duration"`
}

// cowrieTimeLayouts are the timestamp forms Cowrie writes: UTC with a Z, and
// a numeric offset without a colon when it is set to local time.
var cowrieTimeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z0700"}

func parseCowrieTime(s string) (time.Time, bool) {
	for _, layout := range cowrieTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseCowrieLine turns one log line into an event.
func parseCowrieLine(line []byte) (Event, bool) {
	if len(line) == 0 || line[0] != '{' {
		return Event{}, false
	}
	var c cowrieLine
	if err := json.Unmarshal(line, &c); err != nil {
		return Event{}, false
	}
	typ := strings.ToLower(strings.TrimSpace(string(c.EventID)))
	if typ == "" {
		return Event{}, false
	}
	t, ok := parseCowrieTime(strings.TrimSpace(string(c.Timestamp)))
	if !ok {
		return Event{}, false
	}
	e := Event{
		Time:      t,
		Honeypot:  CowrieHoneypot,
		SourceIP:  string(c.SrcIP),
		SessionID: string(c.Session),
		Type:      typ,
		Username:  string(c.Username),
		Password:  string(c.Password),
		Command:   string(c.Input),
		URL:       string(c.URL),
		SHA256:    string(c.Shasum),
	}
	if strings.HasSuffix(typ, ".session.closed") {
		e.ReportedDuration = secondsToDuration(float64(c.Duration))
	}
	return e, true
}

// secondsToDuration converts a honeypot-stated session length. Values that
// are not positive give zero; long ones are cut to maxReported.
func secondsToDuration(sec float64) time.Duration {
	if math.IsNaN(sec) || sec <= 0 {
		return 0
	}
	if sec >= maxReported.Seconds() {
		return maxReported
	}
	return time.Duration(sec * float64(time.Second))
}

// ReadCowrieLog reads a Cowrie JSON log (one object per line) and passes
// every event to emit, until the end of the log or until emit returns false.
// A line that cannot be read as an event is counted and skipped. The error
// is a read error of r, never a bad line.
func ReadCowrieLog(r io.Reader, emit func(Event) bool) (LogStats, error) {
	var st LogStats
	br := bufio.NewReaderSize(r, 64<<10)
	line := make([]byte, 0, 4096)
	tooLong := false
	for {
		frag, err := br.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(frag) > MaxLogLine {
				tooLong = true
				line = line[:0]
			} else {
				line = append(line, frag...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return st, err
		}
		atEOF := err != nil
		if atEOF && len(frag) == 0 && len(line) == 0 && !tooLong {
			return st, nil
		}
		st.Lines++
		text := bytes.TrimSpace(line)
		switch {
		case tooLong:
			st.Oversized++
		case len(text) == 0:
			st.Blank++
		default:
			e, ok := parseCowrieLine(text)
			if !ok {
				st.Malformed++
				break
			}
			st.Events++
			if !emit(e) {
				return st, nil
			}
		}
		line = line[:0]
		tooLong = false
		if atEOF {
			return st, nil
		}
	}
}
