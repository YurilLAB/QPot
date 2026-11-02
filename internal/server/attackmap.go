package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/geo"
)

// The attack map (/map/) is T-Pot's attack map frontend. T-Pot feeds it over a
// WebSocket from a Redis channel filled by a Python poller; QPot serves the
// same "Traffic" and "Stats" messages straight from its own database as a
// stream the page reads with fetch() - which, unlike a WebSocket or
// EventSource, can carry the X-QPot-ID header, so the feed is authenticated
// like every other API call.

const (
	mapPollInterval  = 2 * time.Second
	mapStatsInterval = 10 * time.Second
	mapPingInterval  = 15 * time.Second
	mapBatch         = 500
	mapMaxStreams    = 8
)

// mapTraffic is one attack, in the field names T-Pot's map.js reads.
type mapTraffic struct {
	Type           string  `json:"type"` // "Traffic"
	Protocol       string  `json:"protocol"`
	Color          string  `json:"color"`
	ISOCode        string  `json:"iso_code"`
	Country        string  `json:"country"`
	ContinentCode  string  `json:"continent_code"`
	Honeypot       string  `json:"honeypot"`
	SrcIP          string  `json:"src_ip"`
	SrcPort        int     `json:"src_port"`
	SrcLat         float64 `json:"src_lat"`
	SrcLong        float64 `json:"src_long"`
	DstIP          string  `json:"dst_ip"`
	DstPort        int     `json:"dst_port"`
	DstLat         float64 `json:"dst_lat"`
	DstLong        float64 `json:"dst_long"`
	DstISOCode     string  `json:"dst_iso_code"`
	DstCountryName string  `json:"dst_country_name"`
	IPRep          string  `json:"ip_rep"`
	EventTime      string  `json:"event_time"`
	EventCount     int64   `json:"event_count"`
	TPotHostname   string  `json:"tpot_hostname"`
}

// mapStats is the periodic counter message (attacks in the last 1m/1h/24h).
type mapStats struct {
	Type    string `json:"type"` // "Stats"
	Last1m  int64  `json:"last_1m"`
	Last1h  int64  `json:"last_1h"`
	Last24h int64  `json:"last_24h"`
}

// mapHome is where attacks are drawn to: the configured attack_map location,
// else the country inferred from the host's time zone.
func (s *Server) mapHome() (lat, lon float64, code, name string, ok bool) {
	am := s.config.AttackMap
	if c, found := geo.Lookup(am.Country); found {
		lat, lon, code, name, ok = c.Lat, c.Lon, c.Code, c.Name, true
	} else if c, found := geo.HostCountry(); found {
		lat, lon, code, name, ok = c.Lat, c.Lon, c.Code, c.Name, true
	}
	if am.Latitude != 0 || am.Longitude != 0 {
		lat, lon, ok = am.Latitude, am.Longitude, true
	}
	return lat, lon, code, name, ok
}

// toMapTraffic converts an event; ok is false when the attacker cannot be
// placed (no GeoIP country on the event).
func toMapTraffic(e *database.Event, homeLat, homeLon float64, homeCode, homeName, sensor string, n int64) (mapTraffic, bool) {
	c, found := geo.Lookup(e.Country)
	if !found || strings.TrimSpace(e.SourceIP) == "" {
		return mapTraffic{}, false
	}
	proto, ok := mapPortNames[e.DestPort]
	if !ok {
		proto = "OTHER"
	}
	color := mapServiceColors[proto]
	if color == "" {
		color = mapServiceColors["OTHER"]
	}
	if homeLat == 0 && homeLon == 0 {
		// Unknown sensor location: no line and no sensor marker ("XX" is
		// the map's unknown-country code).
		homeLat, homeLon = c.Lat, c.Lon
		homeCode, homeName = "XX", "Unknown location"
	} else if homeCode == "" {
		homeCode, homeName = "XX", "Sensor"
	}
	return mapTraffic{
		Type: "Traffic", Protocol: proto, Color: color,
		ISOCode: c.Code, Country: c.Name, Honeypot: e.Honeypot,
		SrcIP: e.SourceIP, SrcPort: e.SourcePort, SrcLat: c.Lat, SrcLong: c.Lon,
		DstPort: e.DestPort, DstLat: homeLat, DstLong: homeLon,
		DstISOCode: homeCode, DstCountryName: homeName,
		IPRep: "Reputation Unknown", EventTime: e.Timestamp.UTC().Format("2006-01-02 15:04:05"),
		EventCount: n, TPotHostname: sensor,
	}, true
}

func eventKey(e *database.Event) string {
	return fmt.Sprintf("%d|%s|%s|%d|%s|%s|%s", e.Timestamp.UnixNano(), e.Honeypot, e.SourceIP, e.SourcePort, e.EventType, e.Username, e.Command)
}

var mapStreams atomic.Int32

// handleMapStream streams attack-map messages ("data: <json>\n\n" lines).
func (s *Server) handleMapStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	if mapStreams.Add(1) > mapMaxStreams {
		mapStreams.Add(-1)
		s.sendError(w, http.StatusTooManyRequests, "too many attack map viewers")
		return
	}
	defer mapStreams.Add(-1)

	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(line string) bool {
		// The server's WriteTimeout would end the stream; extend it per write.
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := fmt.Fprint(w, line); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	sendJSON := func(v any) bool {
		b, err := json.Marshal(v)
		if err != nil {
			return true
		}
		return send("data: " + string(b) + "\n\n")
	}

	ctx := r.Context()
	homeLat, homeLon, homeCode, homeName, _ := s.mapHome()
	sensor := s.config.InstanceName

	stats := func() bool {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		m := mapStats{Type: "Stats"}
		for _, win := range []struct {
			d   time.Duration
			dst *int64
		}{{time.Minute, &m.Last1m}, {time.Hour, &m.Last1h}, {24 * time.Hour, &m.Last24h}} {
			if st, err := s.database.GetStats(qctx, time.Now().Add(-win.d)); err == nil && st != nil {
				*win.dst = st.TotalEvents
			}
		}
		return sendJSON(m)
	}

	// Start with the last minute so the map is not empty on open.
	since := time.Now().Add(-time.Minute)
	seen := map[string]time.Time{}
	var count int64
	traffic := func() bool {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		// Second-precision backends may return events from the boundary
		// second again; seen de-duplicates them.
		evs, err := s.database.GetEvents(qctx, database.EventFilter{StartTime: since.Add(-time.Second), Limit: mapBatch})
		if err != nil {
			slog.Debug("attack map: GetEvents failed", "error", err)
			return true
		}
		// Oldest first, so lines animate in the order attacks happened.
		for i := len(evs) - 1; i >= 0; i-- {
			e := evs[i]
			k := eventKey(e)
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = e.Timestamp
			if e.Timestamp.After(since) {
				since = e.Timestamp
			}
			count++
			if m, ok := toMapTraffic(e, homeLat, homeLon, homeCode, homeName, sensor, count); ok {
				if !sendJSON(m) {
					return false
				}
			}
		}
		for k, ts := range seen {
			if ts.Before(since.Add(-5 * time.Second)) {
				delete(seen, k)
			}
		}
		return true
	}

	if !stats() || !traffic() {
		return
	}
	poll := time.NewTicker(mapPollInterval)
	defer poll.Stop()
	statTick := time.NewTicker(mapStatsInterval)
	defer statTick.Stop()
	ping := time.NewTicker(mapPingInterval)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			if !traffic() {
				return
			}
		case <-statTick.C:
			if !stats() {
				return
			}
		case <-ping.C:
			if !send(": ping\n\n") {
				return
			}
		}
	}
}
