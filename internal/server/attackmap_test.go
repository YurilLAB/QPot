package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/geo"
)

// mapDB returns the same recent events on every poll (as a backend with
// second-precision timestamps does at the window boundary), newest first.
type mapDB struct {
	fakeDB
	events []*database.Event
}

func (m *mapDB) GetEvents(ctx context.Context, f database.EventFilter) ([]*database.Event, error) {
	var out []*database.Event
	for _, e := range m.events {
		if !e.Timestamp.Before(f.StartTime) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *mapDB) GetStats(ctx context.Context, since time.Time) (*database.Stats, error) {
	return &database.Stats{TotalEvents: int64(len(m.events))}, nil
}

func TestToMapTraffic(t *testing.T) {
	now := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	e := &database.Event{Timestamp: now, Honeypot: "cowrie", SourceIP: "8.8.8.8", SourcePort: 4444, DestPort: 22, Country: "us"}
	m, ok := toMapTraffic(e, 51.17, 10.45, "DE", "Germany", "sensor1", 7)
	if !ok {
		t.Fatal("event with a country was not placed")
	}
	if m.Type != "Traffic" || m.Protocol != "SSH" || m.ISOCode != "US" || m.Country != "United States" ||
		m.DstLat != 51.17 || m.DstISOCode != "DE" || m.EventCount != 7 || m.TPotHostname != "sensor1" ||
		m.EventTime != "2026-11-02 08:00:00" || m.Color == "" {
		t.Errorf("unexpected traffic message: %+v", m)
	}

	e.DestPort = 31337
	if m, _ := toMapTraffic(e, 0, 0, "", "", "s", 1); m.Protocol != "OTHER" || m.Color != mapServiceColors["OTHER"] {
		t.Errorf("unknown port: %+v", m)
	}
	// Unknown sensor location: a point at the attacker's country with the
	// map's unknown code, so no line or sensor marker is drawn.
	if m, _ := toMapTraffic(e, 0, 0, "", "", "s", 1); m.DstLat != m.SrcLat || m.DstLong != m.SrcLong || m.DstISOCode != "XX" {
		t.Errorf("no home: want a point, got %+v", m)
	}
	for _, c := range []string{"", "unknown", "ZZ", "<script>"} {
		e.Country = c
		if _, ok := toMapTraffic(e, 0, 0, "", "", "s", 1); ok {
			t.Errorf("country %q should not be placed", c)
		}
	}
	e.Country, e.SourceIP = "US", " "
	if _, ok := toMapTraffic(e, 0, 0, "", "", "s", 1); ok {
		t.Error("event without a source IP should not be placed")
	}
}

func TestMapHome(t *testing.T) {
	s := &Server{config: &config.Config{AttackMap: config.AttackMapConfig{Country: "de"}}}
	lat, lon, code, name, ok := s.mapHome()
	if !ok || code != "DE" || name != "Germany" || lat == 0 || lon == 0 {
		t.Errorf("country home: %v %v %q %q %v", lat, lon, code, name, ok)
	}
	s.config.AttackMap.Latitude, s.config.AttackMap.Longitude = 52.52, 13.40
	if lat, lon, code, _, ok := s.mapHome(); !ok || lat != 52.52 || lon != 13.40 || code != "DE" {
		t.Errorf("explicit coordinates: %v %v %q %v", lat, lon, code, ok)
	}
}

func TestHandleMapStream(t *testing.T) {
	now := time.Now()
	db := &mapDB{events: []*database.Event{
		{Timestamp: now.Add(-2 * time.Second), Honeypot: "cowrie", SourceIP: "203.0.113.5", DestPort: 22, Country: "GB"},
		{Timestamp: now.Add(-3 * time.Second), Honeypot: "dionaea", SourceIP: "10.0.0.1", DestPort: 445}, // no country
		{Timestamp: now.Add(-10 * time.Minute), Honeypot: "cowrie", SourceIP: "203.0.113.6", DestPort: 22, Country: "US"},
	}}
	s := &Server{config: &config.Config{InstanceName: "t", AttackMap: config.AttackMapConfig{Country: "DE"}}, database: db}
	ts := httptest.NewServer(http.HandlerFunc(s.handleMapStream))
	defer ts.Close()

	// Long enough for the initial send plus at least one poll, which returns
	// the same events again and must not repeat them.
	ctx, cancel := context.WithTimeout(context.Background(), mapPollInterval+1500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type %q", ct)
	}
	var traffic []mapTraffic
	stats := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var probe struct{ Type string }
		if err := json.Unmarshal([]byte(data), &probe); err != nil {
			t.Fatalf("bad message %q: %v", data, err)
		}
		switch probe.Type {
		case "Stats":
			stats++
		case "Traffic":
			var m mapTraffic
			_ = json.Unmarshal([]byte(data), &m)
			traffic = append(traffic, m)
		default:
			t.Errorf("unexpected message type %q", probe.Type)
		}
	}
	if stats == 0 {
		t.Error("no Stats message")
	}
	// Only the recent event with a country; the old one is outside the
	// initial window and the unplaceable one is skipped.
	if len(traffic) != 1 || traffic[0].SrcIP != "203.0.113.5" || traffic[0].DstISOCode != "DE" {
		t.Errorf("traffic = %+v, want exactly the GB event once", traffic)
	}
}

func TestHandleMapStreamLimits(t *testing.T) {
	s := &Server{config: &config.Config{}, database: &mapDB{}}
	rec := httptest.NewRecorder()
	s.handleMapStream(rec, httptest.NewRequest(http.MethodPost, "/api/map/stream", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}

	mapStreams.Add(mapMaxStreams)
	defer mapStreams.Add(-mapMaxStreams)
	rec = httptest.NewRecorder()
	s.handleMapStream(rec, httptest.NewRequest(http.MethodGet, "/api/map/stream", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("over the viewer limit: %d, want 429", rec.Code)
	}

	none := &Server{config: &config.Config{}}
	rec = httptest.NewRecorder()
	none.handleMapStream(rec, httptest.NewRequest(http.MethodGet, "/api/map/stream", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no database: %d, want 503", rec.Code)
	}
}

// FuzzToMapTraffic feeds attacker-influenced event fields (the country comes
// from GeoIP of the source address, the rest from honeypot logs) through the
// map conversion: it must never panic, place only known countries, and
// always produce a message the browser can parse.
func FuzzToMapTraffic(f *testing.F) {
	f.Add("US", "8.8.8.8", 4444, 22, "cowrie")
	f.Add("", "", 0, 0, "")
	f.Add("unknown", "::1", -1, 70000, "x")
	f.Add("de", "203.0.113.1", 1, 65535, "<script>alert(1)</script>")
	f.Fuzz(func(t *testing.T, country, ip string, sport, dport int, hp string) {
		e := &database.Event{Timestamp: time.Unix(0, 0), Country: country, SourceIP: ip, SourcePort: sport, DestPort: dport, Honeypot: hp}
		m, ok := toMapTraffic(e, 1, 2, "DE", "Germany", "s", 1)
		if !ok {
			return
		}
		if len(m.ISOCode) != 2 || m.Country == "" || m.Protocol == "" || m.Color == "" {
			t.Fatalf("placed an event with incomplete data: %+v", m)
		}
		b, err := json.Marshal(m)
		if err != nil || !json.Valid(b) {
			t.Fatalf("message does not marshal: %v", err)
		}
	})
}

// firstMapStats reads the first Stats message of s's attack map stream.
func firstMapStats(t *testing.T, s *Server) map[string]any {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(s.handleMapStream))
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(data), &m); err != nil {
			t.Fatalf("bad message %q: %v", data, err)
		}
		if m["type"] == "Stats" {
			return m
		}
	}
	t.Fatal("no Stats message")
	return nil
}

// The Stats message carries the sensor's own place (as Traffic's dst_*), so
// the map can pin a sensor no attack has reached yet; nothing when the place
// is unknown.
func TestMapStatsCarrySensorPlace(t *testing.T) {
	t.Setenv("TZ", "Etc/UTC") // a zone of no country: the host gives no place
	db := &mapDB{}            // a quiet sensor: no events
	au, _ := geo.Lookup("AU")

	s := &Server{config: &config.Config{InstanceName: "t", AttackMap: config.AttackMapConfig{Country: "au"}}, database: db}
	m := firstMapStats(t, s)
	if m["dst_lat"] != au.Lat || m["dst_long"] != au.Lon || m["dst_iso_code"] != "AU" || m["dst_country_name"] != au.Name {
		t.Errorf("country: %v", m)
	}
	if _, ok := m["last_24h"]; !ok {
		t.Errorf("counters missing: %v", m)
	}

	s.config.AttackMap = config.AttackMapConfig{Latitude: -16.92, Longitude: 145.77}
	if m := firstMapStats(t, s); m["dst_lat"] != -16.92 || m["dst_long"] != 145.77 || m["dst_iso_code"] != "XX" {
		t.Errorf("coordinates only: %v", m)
	}

	s.config.AttackMap = config.AttackMapConfig{}
	m = firstMapStats(t, s)
	for _, k := range []string{"dst_lat", "dst_long", "dst_iso_code", "dst_country_name"} {
		if _, ok := m[k]; ok {
			t.Errorf("unknown place, but %s = %v", k, m[k])
		}
	}
}
