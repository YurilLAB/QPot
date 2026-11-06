package server

// Canary (honeytoken) subsystem HTTP surface and event wiring.
//
// Canaries are decoy artifacts planted inside the operator's real estate that
// fire a high-fidelity alert on any interaction. Two trip channels:
//   - the PUBLIC beacon (/c/<token>) — an HTTP GET of a web/file token, and
//   - the intelligence worker — a planted credential value seen in a captured
//     honeypot session (see canaryMatcher).
// Every trip becomes a database.Event tagged honeypot="canary" via onCanaryTrip.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

// clientIP returns the TCP peer IP of the request (the real, un-spoofable
// source). X-Forwarded-For is intentionally NOT trusted as the source — an
// attacker controls it — but a present XFF is captured separately for context.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// firstForwarded returns the first hop of an X-Forwarded-For header, trimmed.
func firstForwarded(xff string) string {
	if i := strings.IndexByte(xff, ','); i >= 0 {
		xff = xff[:i]
	}
	return strings.TrimSpace(xff)
}

// plantedRecheck is the least time between two looks at the instance's config
// file for a change of what its honeypots plant (see followPlanted).
var plantedRecheck = 5 * time.Second

// maxPlantedConfig bounds the config file read for such a look.
const maxPlantedConfig = 4 << 20

// plantedFollower is the state of followPlanted: when it last looked at the
// config file and the hash of what it read then.
type plantedFollower struct {
	mu      sync.Mutex
	checked time.Time
	read    bool
	sum     [sha256.Size]byte
}

// followPlanted keeps the store's planted canaries those the instance plants
// now. The CLI changes them while the server runs on: qpot honeypot enable
// cowrie, set cowrie persona=... or bait=on|off and a canary.base_url change
// each save the config file and recreate Cowrie with the new bait, and this
// server read the file once, at its start. So before a store read that
// matters (an event matched, a beacon hit, the API's list) it looks at the
// file again, at most once per plantedRecheck, and when the file's contents
// changed, syncs the planted canaries of what it says now, as a restarted
// server would (with this server's QPot ID, which a start takes from the ID
// file). A file that cannot be read or parsed changes nothing.
func (s *Server) followPlanted() {
	if s.canaries == nil || s.config == nil || s.config.ConfigPath == "" {
		return
	}
	f := &s.planted
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.read && now.Sub(f.checked) < plantedRecheck {
		return
	}
	f.checked = now
	path := s.config.ConfigPath
	data, err := readConfigBounded(path)
	if err != nil {
		slog.Debug("canary: config file not read for the planted canaries", "path", path, "error", err)
		return
	}
	sum := sha256.Sum256(data)
	if f.read && sum == f.sum {
		return
	}
	f.read, f.sum = true, sum
	cfg, err := config.Parse(data, path)
	if err != nil {
		slog.Warn("canary: config file changed but does not parse; planted canaries kept", "path", path, "error", err)
		return
	}
	cfg.QPotID = s.config.QPotID
	if err := s.canaries.SyncPlanted(instance.PlantedCanaries(cfg)); err != nil {
		slog.Warn("Canary store: could not save the planted canaries", "error", err)
	}
}

// readConfigBounded reads a config file of at most maxPlantedConfig bytes.
func readConfigBounded(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxPlantedConfig+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPlantedConfig {
		return nil, fmt.Errorf("config file larger than %d bytes", maxPlantedConfig)
	}
	return data, nil
}

// handleCanaryBeacon serves the public canary URL. Any GET of /c/<token>
// records a trip and returns an innocuous decoy. The response is identical
// whether or not the token exists, so the endpoint is not a token-enumeration
// oracle (and the tokens are high-entropy regardless).
func (s *Server) handleCanaryBeacon(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/c/")
	// A trip needs a single well-formed token segment fetched with GET/HEAD;
	// anything else still gets the same decoy so the endpoint stays silent.
	if token != "" && !strings.Contains(token, "/") &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) {
		detail := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			detail += " xff=" + firstForwarded(xff)
		}
		ua := r.Header.Get("User-Agent")
		s.followPlanted()
		// A persistence error does not undo the in-memory trip, so still alert.
		// Detach from the request context: a client that hangs up right away
		// must not cancel the alert's DB insert.
		trip, ok, err := s.canaries.TripByToken(token, clientIP(r), ua, detail)
		if err != nil {
			slog.Error("canary: failed to persist trip to store", "error", err)
		}
		if ok {
			s.onCanaryTrip(context.WithoutCancel(r.Context()), trip)
		}
	}
	s.serveCanaryDecoy(w)
}

// serveCanaryDecoy writes the configured innocuous response for a beacon hit.
func (s *Server) serveCanaryDecoy(w http.ResponseWriter) {
	switch s.config.Canary.Decoy {
	case "pixel":
		// 1x1 transparent GIF — what an <img>/document beacon expects back.
		gif := []byte{
			0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
		}
		w.Header().Set("Content-Type", "image/gif")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		w.Write(gif)
	default: // "notfound"
		http.Error(w, "404 page not found", http.StatusNotFound)
	}
}

// onCanaryTrip is invoked once per recorded trip (from either channel). It logs
// a high-visibility alert and emits the trip as a classified canary event into
// the events pipeline so it shows up in the feed, IOC store and overview.
func (s *Server) onCanaryTrip(ctx context.Context, trip *canary.Trip) {
	slog.Warn("CANARY TRIPPED",
		"canary_id", trip.CanaryID, "name", trip.Name, "kind", trip.Kind,
		"channel", trip.Channel, "source_ip", trip.SourceIP, "memo", trip.Memo)

	if s.database == nil {
		return
	}
	event := trip.ToEvent()
	var iocs []*database.IOC
	if s.classifier != nil {
		iocs = s.classifier.ExtractIOCs(event)
	}
	// Bounded context so a slow DB never blocks the calling goroutine.
	insCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.database.InsertEvent(insCtx, event); err != nil {
		slog.Error("canary: failed to insert trip event", "error", err)
	}
	if len(iocs) > 0 {
		if err := s.database.InsertIOCs(insCtx, iocs); err != nil {
			slog.Warn("canary: failed to insert trip IOCs", "error", err)
		}
	}
}

// canaryView renders a canary for an API response, including the beacon URL for
// web/file canaries and the credential pair for AWS canaries.
func (s *Server) canaryView(c *canary.Canary) map[string]interface{} {
	m := map[string]interface{}{
		"id":         c.ID,
		"kind":       c.Kind,
		"name":       c.Name,
		"memo":       c.Memo,
		"enabled":    c.Enabled,
		"created_at": c.CreatedAt,
		"trips":      c.Trips,
		"last_trip":  c.LastTrip,
	}
	if c.Kind == canary.KindWeb || c.Kind == canary.KindFile {
		m["url"] = c.URL(s.config.Canary.BaseURL)
	}
	if c.Kind == canary.KindAWS {
		m["access_key_id"] = c.AccessKeyID
		m["secret_access_key"] = c.SecretAccessKey
	}
	if c.Kind == canary.KindCredential || c.Kind == canary.KindSSHKey {
		m["values"] = c.Values
	}
	if c.PublicKey != "" {
		m["public_key"] = c.PublicKey
	}
	if c.Planted {
		m["planted"] = true
	}
	return m
}

// handleCanaries lists and creates canaries, and deletes one by ?id=.
func (s *Server) handleCanaries(w http.ResponseWriter, r *http.Request) {
	s.followPlanted()
	switch r.Method {
	case http.MethodGet:
		list := s.canaries.List()
		out := make([]map[string]interface{}, 0, len(list))
		for _, c := range list {
			out = append(out, s.canaryView(c))
		}
		s.sendJSON(w, map[string]interface{}{"qpot_id": s.config.QPotID, "canaries": out})

	case http.MethodPost:
		var req struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
			Memo string `json:"memo"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.sendError(w, http.StatusBadRequest, "invalid request")
			return
		}
		kind := canary.Kind(strings.ToLower(strings.TrimSpace(req.Kind)))
		if !kind.Creatable() {
			s.sendError(w, http.StatusBadRequest, "kind must be one of: web, file, aws")
			return
		}
		c, err := s.canaries.Create(kind, req.Name, req.Memo)
		if err != nil {
			s.sendInternalError(w, "create canary failed", err)
			return
		}
		s.sendJSON(w, s.canaryView(c))

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			s.sendError(w, http.StatusBadRequest, "id is required")
			return
		}
		ok, err := s.canaries.Delete(id)
		if errors.Is(err, canary.ErrPlanted) {
			s.sendError(w, http.StatusConflict, err.Error())
			return
		}
		if err != nil {
			s.sendInternalError(w, "delete canary failed", err)
			return
		}
		if !ok {
			s.sendError(w, http.StatusNotFound, "canary not found")
			return
		}
		s.sendJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCanaryTrips returns recent canary trips, newest first.
func (s *Server) handleCanaryTrips(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			limit = n
		}
	}
	s.sendJSON(w, map[string]interface{}{
		"qpot_id": s.config.QPotID,
		"trips":   s.canaries.Trips(limit),
	})
}

// handleCanaryArtifact downloads the document artifact for a file canary
// (GET /api/canaries/artifact?id=cnry_...). Only file canaries have one.
func (s *Server) handleCanaryArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	c, ok := s.canaries.Get(id)
	if !ok {
		s.sendError(w, http.StatusNotFound, "canary not found")
		return
	}
	name, body, err := c.RenderFile(s.config.Canary.BaseURL)
	if err != nil {
		s.sendError(w, http.StatusBadRequest, "canary is not a file canary")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// canaryMatcher adapts the server to the intelligence.CanaryMatcher interface,
// scanning each classified event's text for any planted credential value.
type canaryMatcher struct{ s *Server }

// MatchEvent builds the searchable text of an event and asks the canary store
// whether it contains a planted value. On a hit the store records the trip and
// this emits it into the events pipeline. Returns true when a canary tripped.
func (m *canaryMatcher) MatchEvent(ctx context.Context, event *database.Event) bool {
	m.s.followPlanted()
	if m.s.canaries == nil || !m.s.canaries.HasWatchValues() {
		return false
	}
	var b strings.Builder
	b.WriteString(event.Command)
	b.WriteByte('\n')
	b.WriteString(event.Username)
	b.WriteByte('\n')
	b.WriteString(event.Password)
	if len(event.Payload) > 0 {
		b.WriteByte('\n')
		b.Write(event.Payload)
	}
	for _, v := range event.Metadata {
		b.WriteByte('\n')
		b.WriteString(v)
	}
	detail := "matched in " + event.Honeypot + " session"
	trips, err := m.s.canaries.MatchAll(b.String(), event.SourceIP, detail)
	if err != nil {
		slog.Error("canary: failed to persist matched trip", "error", err)
	}
	for _, trip := range trips {
		m.s.onCanaryTrip(ctx, trip)
	}
	return len(trips) > 0
}
