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
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
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
		if trip, ok, err := s.canaries.TripByToken(token, clientIP(r), ua, detail); err != nil {
			slog.Error("canary: failed to persist trip to store", "error", err)
		} else if ok {
			s.onCanaryTrip(r.Context(), trip)
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
// the events pipeline so it shows up in the feed, IOC store, Yuril, and ypanel.
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
		if s.forwarder != nil {
			batchID := fmt.Sprintf("qpot-canary-%d", time.Now().UnixNano())
			if err := s.forwarder.Forward(insCtx, batchID, iocs); err != nil {
				slog.Warn("canary: failed to forward trip IOCs to Yuril", "error", err)
			}
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
	return m
}

// handleCanaries lists and creates canaries, and deletes one by ?id=.
func (s *Server) handleCanaries(w http.ResponseWriter, r *http.Request) {
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
		if !kind.Valid() {
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
	trip, ok, err := m.s.canaries.Match(b.String(), event.SourceIP, detail)
	if err != nil {
		slog.Error("canary: failed to persist matched trip", "error", err)
	}
	if ok {
		m.s.onCanaryTrip(ctx, trip)
	}
	return ok
}
