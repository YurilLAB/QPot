package intelligence

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// The kinds of strong campaign evidence, as EventEvidence names them.
const (
	EvidencePayload  = "payload"
	EvidenceHost     = "host"
	EvidenceCommand  = "command"
	EvidenceSequence = "command-sequence"
)

// Evidence is one piece of strong campaign evidence, in the clear. The
// campaign builder compares only Key, a hash, so that attacker text of any
// length costs it a fixed size; Value is what an investigator reads.
type Evidence struct {
	// Kind is EvidencePayload, EvidenceHost, EvidenceCommand or
	// EvidenceSequence.
	Kind string `json:"kind"`
	// Key is what the campaign builder stores and compares.
	Key string `json:"key"`
	// Value is the payload's SHA-256, the download host, the command with
	// its whitespace normalised, or the commands of a sequence, one a line.
	Value string `json:"value"`
}

// EventEvidence returns the strong evidence one event shows: the download
// hosts its command and payload name, its normalised shell command and the
// hash of a file it transferred. The campaign builder records exactly these
// (TTPBuilder.observe reads them through this function), so what a case
// shows as the reason for a link is what made the link.
func EventEvidence(event *database.Event) []Evidence {
	if event == nil {
		return nil
	}
	var out []Evidence
	host := func(_, h string) {
		// A private or loopback host is each victim's own, not shared
		// infrastructure; hostIOC drops those and anything that is no host.
		if typ, v := hostIOC(h); typ != "" {
			out = append(out, Evidence{Kind: EvidenceHost, Key: kindHost + hash128(domainHost, v), Value: v})
		}
	}
	// The command field of an NSM sensor is its own text, not attacker input.
	if event.Command != "" && !sensorText(event) {
		eachLocation(refang(event.Command), host)
		if isCommandEvent(event.EventType) {
			// Whitespace is all that is normalised: the same script sends the
			// same text, and anything looser would link different ones.
			if cmd := strings.Join(strings.Fields(event.Command), " "); cmd != "" {
				out = append(out, Evidence{Kind: EvidenceCommand, Key: hash128(domainCommand, cmd), Value: cmd})
			}
		}
	}
	if text := payloadLocationText(event); text != "" {
		eachLocation(text, host)
	}
	if h := payloadSHA256(event); h != "" && h != emptySHA256 {
		out = append(out, Evidence{Kind: EvidencePayload, Key: kindPayload + hash128(domainPayload, h), Value: h})
	}
	return out
}

// SessionEvidence is one piece of a session's strong evidence and the events
// that show it.
type SessionEvidence struct {
	Evidence
	// At is the time of the earliest event showing it; a sequence is dated
	// by its last command.
	At time.Time `json:"at"`
	// Events are the indexes, into the events given to CollectEvidence, of
	// the events that show it, in the order given.
	Events []int `json:"-"`
}

// CollectEvidence returns the strong evidence a session's events show, held
// to the campaign builder's limits: the maxSessionEvidence earliest hosts and
// payloads, and a command sequence once there are sequenceCommands distinct
// commands. Two sessions are one campaign when the sets returned for them
// share a key (single commands do not count: only the sequence links).
//
// The builder's total limits (maxEvidenceEntries) are not applied: under
// them a session may have recorded less than its events show.
func CollectEvidence(events []*database.Event) []SessionEvidence {
	var strong, commands []sighting
	values := map[string]Evidence{}
	shown := map[string][]int{}
	for i, event := range events {
		if event == nil || event.Timestamp.IsZero() {
			continue
		}
		for _, e := range EventEvidence(event) {
			if e.Kind == EvidenceCommand {
				commands, _ = addEarliest(commands, e.Key, event.Timestamp, sequenceCommands, true)
			} else {
				strong, _ = addEarliest(strong, e.Key, event.Timestamp, maxSessionEvidence, true)
			}
			values[e.Key] = e
			shown[e.Key] = append(shown[e.Key], i)
		}
	}
	out := make([]SessionEvidence, 0, len(strong)+1)
	for _, s := range strong {
		out = append(out, SessionEvidence{Evidence: values[s.Key], At: s.At, Events: shown[s.Key]})
	}
	if len(commands) == sequenceCommands {
		keys := make([]string, len(commands))
		lines := make([]string, len(commands))
		var from []int
		for i, c := range commands {
			keys[i] = c.Key
			lines[i] = values[c.Key].Value
			from = append(from, shown[c.Key]...)
		}
		sort.Ints(from)
		out = append(out, SessionEvidence{
			Evidence: Evidence{Kind: EvidenceSequence, Key: kindSequence + hash128(domainSequence, keys...), Value: strings.Join(lines, "\n")},
			At:       commands[len(commands)-1].At,
			Events:   from,
		})
	}
	return out
}

// SessionSourceHash returns the part of a session ID that names the event's
// source: every event of one session has the same value, and it is the text
// before the "-" of that session's ID. unknown is true for an event that
// belongs to a honeypot's "unknown source" bucket, which is no single actor.
func SessionSourceHash(event *database.Event) (hash string, unknown bool) {
	if event == nil {
		return "", true
	}
	source, known := sessionSource(event)
	return hash128(domainSession, source), !known
}

// SplitSessionID returns the source hash and the start of a session ID made
// by the campaign builder ("<32 hex>-<unix nanoseconds>"). ok is false for
// any other text, such as the ID of a session stored by an early version.
func SplitSessionID(id string) (sourceHash string, started time.Time, ok bool) {
	hash, nanos, found := strings.Cut(id, "-")
	if !found || len(hash) != 32 || strings.Trim(hash, "0123456789abcdef") != "" {
		return "", time.Time{}, false
	}
	n, err := strconv.ParseInt(nanos, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != nanos {
		return "", time.Time{}, false
	}
	return hash, time.Unix(0, n).UTC(), true
}

// SequenceLength is how many distinct shell commands make a command sequence.
const SequenceLength = sequenceCommands

// IsCommandEvent reports whether an event type is a shell command the
// visitor ran (Cowrie's cowrie.command.input, the HiFi backend's
// ssh-proxy.command.finish), which is what the campaign builder counts
// towards a command sequence.
func IsCommandEvent(eventType string) bool { return isCommandEvent(eventType) }
