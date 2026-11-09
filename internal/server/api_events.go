package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// GET /api/events: the captured events, newest first, with the event
// browser's filters and paging.

const (
	defaultEventLimit = 100
	maxEventLimit     = 1000
	maxEventOffset    = 100000
	// maxEventFilterValues bounds each list filter (honeypot, source_ip, ...).
	maxEventFilterValues = 20
)

var (
	eventHoneypotRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	eventTypeRe     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	eventCountryRe  = regexp.MustCompile(`^[A-Za-z]{2}$`)
)

// eventFilterError is a bad query parameter of GET /api/events.
type eventFilterError struct{ param, msg string }

func (e *eventFilterError) Error() string { return e.param + ": " + e.msg }

// listParam returns a repeatable parameter's values; each may also hold
// several, comma-separated. Empty ones are dropped.
func listParam(q url.Values, name string) ([]string, error) {
	var out []string
	for _, v := range q[name] {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	if len(out) > maxEventFilterValues {
		return nil, &eventFilterError{name, fmt.Sprintf("at most %d values", maxEventFilterValues)}
	}
	return out, nil
}

// parseEventTime reads RFC 3339 or unix seconds.
func parseEventTime(name, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 && n < 1<<37 {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, &eventFilterError{name, "must be an RFC 3339 time (2026-11-07T10:00:00Z) or unix seconds"}
}

// parseIntParam reads an integer parameter in [lo, hi], def when absent.
func parseIntParam(q url.Values, name string, def, lo, hi int) (int, error) {
	v := q.Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, &eventFilterError{name, fmt.Sprintf("must be a whole number from %d to %d", lo, hi)}
	}
	return n, nil
}

// parseEventFilter turns GET /api/events' query into a database filter. Every
// value is checked here and reaches the database only as a parameter.
func parseEventFilter(q url.Values) (database.EventFilter, error) {
	var f database.EventFilter
	var err error
	if f.Honeypots, err = listParam(q, "honeypot"); err != nil {
		return f, err
	}
	for _, h := range f.Honeypots {
		if !eventHoneypotRe.MatchString(h) {
			return f, &eventFilterError{"honeypot", "names use lower-case letters, digits and hyphens"}
		}
	}
	if f.SourceIPs, err = listParam(q, "source_ip"); err != nil {
		return f, err
	}
	for i, ip := range f.SourceIPs {
		a, err := netip.ParseAddr(ip)
		if err != nil || a.Zone() != "" {
			return f, &eventFilterError{"source_ip", "must be IPv4 or IPv6 addresses"}
		}
		f.SourceIPs[i] = a.String() // the form events store (2001:db8::1)
	}
	if f.EventTypes, err = listParam(q, "event_type"); err != nil {
		return f, err
	}
	for _, t := range f.EventTypes {
		if !eventTypeRe.MatchString(t) {
			return f, &eventFilterError{"event_type", "uses letters, digits and . _ : - (at most 64)"}
		}
	}
	if f.Countries, err = listParam(q, "country"); err != nil {
		return f, err
	}
	for i, c := range f.Countries {
		if !eventCountryRe.MatchString(c) {
			return f, &eventFilterError{"country", "must be two-letter country codes"}
		}
		f.Countries[i] = strings.ToUpper(c)
	}
	if f.Categories, err = listParam(q, "category"); err != nil {
		return f, err
	}
	for _, c := range f.Categories {
		if !intelligence.IsCategory(c) {
			return f, &eventFilterError{"category", "must be attack category IDs (GET /api/categories lists them)"}
		}
	}
	if f.StartTime, err = parseEventTime("since", q.Get("since")); err != nil {
		return f, err
	}
	if f.EndTime, err = parseEventTime("until", q.Get("until")); err != nil {
		return f, err
	}
	if !f.StartTime.IsZero() && !f.EndTime.IsZero() && f.EndTime.Before(f.StartTime) {
		return f, &eventFilterError{"until", "is before since"}
	}
	text := q.Get("q")
	switch {
	case len(text) > database.MaxEventText:
		return f, &eventFilterError{"q", fmt.Sprintf("is longer than %d bytes", database.MaxEventText)}
	case !utf8.ValidString(text) || strings.ContainsFunc(text, unicode.IsControl):
		return f, &eventFilterError{"q", "may not contain control characters"}
	}
	f.Text = text
	if f.Limit, err = parseIntParam(q, "limit", defaultEventLimit, 1, maxEventLimit); err != nil {
		return f, err
	}
	if f.Offset, err = parseIntParam(q, "offset", 0, 0, maxEventOffset); err != nil {
		return f, err
	}
	return f, nil
}

// eventsPage is the answer of GET /api/events.
type eventsPage struct {
	Events     []*database.Event `json:"events"`
	Limit      int               `json:"limit"`
	Offset     int               `json:"offset"`
	HasMore    bool              `json:"has_more"`
	NextOffset int               `json:"next_offset,omitempty"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	f, err := parseEventFilter(r.URL.Query())
	if err != nil {
		var fe *eventFilterError
		if errors.As(err, &fe) {
			s.sendAPIError(w, http.StatusBadRequest, "", "Bad filter: "+fe.Error()+".")
			return
		}
		s.sendInternalError(w, "events filter", err)
		return
	}
	if s.db() == nil {
		s.sendAPIError(w, http.StatusServiceUnavailable, "QP-INST-005", "The database is not available.")
		return
	}
	page := eventsPage{Limit: f.Limit, Offset: f.Offset}
	// One more than asked tells whether there is a next page.
	q := f
	q.Limit = f.Limit + 1
	events, err := s.db().GetEvents(r.Context(), q)
	if err != nil {
		s.sendInternalError(w, "get events failed", err)
		return
	}
	if len(events) > f.Limit {
		events = events[:f.Limit]
		page.HasMore, page.NextOffset = true, f.Offset+f.Limit
	}
	if events == nil {
		events = []*database.Event{}
	}
	page.Events = events
	writeJSON(w, http.StatusOK, page)
}
