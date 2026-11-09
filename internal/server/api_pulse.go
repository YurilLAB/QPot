package server

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/geo"
)

// GET /api/pulse?range=24h|1h|1m: the landing page's timeline of attacks,
// as T-Pot's landing page asks Elasticsearch for it, already reduced: the
// counts per slot of the range and of the range before it, the busiest
// honeypots with their own counts, and the top sources.

// pulseRange is one range the landing page offers: points slots of step.
type pulseRange struct {
	points int
	step   time.Duration
}

var pulseRanges = map[string]pulseRange{
	"24h": {48, 30 * time.Minute},
	"1h":  {60, time.Minute},
	"1m":  {30, 2 * time.Second},
}

const (
	pulseTypes   = 7
	pulseSources = 12
	// pulseReuse is how long an answer is given again per range (the page
	// asks every few seconds, from every open tab).
	pulseReuse = 2 * time.Second
)

type pulseSlot struct {
	Key int64 `json:"key"` // the slot's start, unix milliseconds
	N   int64 `json:"n"`
}

type pulseType struct {
	Type  string      `json:"type"`
	N     int64       `json:"n"`
	Slots []pulseSlot `json:"slots"`
}

type pulseSource struct {
	IP      string `json:"ip"`
	N       int64  `json:"n"`
	Country string `json:"country"`
	Rep     string `json:"rep"`
}

type pulseSensor struct {
	Name   string `json:"name"`
	N      int64  `json:"n"`
	Latest int64  `json:"latest,omitempty"`
}

type pulseAnswer struct {
	Range      string        `json:"range"`
	Total      int64         `json:"total"`
	Previous   int64         `json:"previous"`
	Slots      []pulseSlot   `json:"slots"`
	Before     []pulseSlot   `json:"before"`
	Types      []pulseType   `json:"types"`
	Sources    int64         `json:"sources"`
	Honeypots  int           `json:"honeypots"`
	Latest     int64         `json:"latest,omitempty"`
	TopSources []pulseSource `json:"top_sources"`
	Sensors    []pulseSensor `json:"sensors"`
}

// pulseCache keeps the last answer per range.
type pulseCache struct {
	mu   sync.Mutex
	last map[string]pulseCached
}

type pulseCached struct {
	at  time.Time
	ans *pulseAnswer
}

// pulseWindow returns the start of the range that ends with the slot now is
// in. Slots are aligned to the step (from midnight UTC), so a slot keeps its
// key from one answer to the next.
func pulseWindow(now time.Time, pr pulseRange) time.Time {
	end := now.UTC().Truncate(pr.step).Add(pr.step)
	return end.Add(-time.Duration(pr.points) * pr.step)
}

// buildPulse reduces slot counts of the range before and the range (2 *
// points slots from before) to the answer's timelines and types.
func buildPulse(name string, pr pulseRange, start time.Time, counts []database.SlotCount) *pulseAnswer {
	a := &pulseAnswer{Range: name, Types: []pulseType{}, TopSources: []pulseSource{}, Sensors: []pulseSensor{}}
	slots := func(from time.Time) []pulseSlot {
		out := make([]pulseSlot, pr.points)
		for i := range out {
			out[i].Key = from.Add(time.Duration(i) * pr.step).UnixMilli()
		}
		return out
	}
	a.Before = slots(start.Add(-time.Duration(pr.points) * pr.step))
	a.Slots = slots(start)
	byType := map[string]*pulseType{}
	for _, c := range counts {
		switch {
		case c.Slot >= 0 && c.Slot < pr.points:
			a.Before[c.Slot].N += c.Count
			a.Previous += c.Count
		case c.Slot >= pr.points && c.Slot < 2*pr.points:
			i := c.Slot - pr.points
			a.Slots[i].N += c.Count
			a.Total += c.Count
			t := byType[c.Honeypot]
			if t == nil {
				t = &pulseType{Type: c.Honeypot, Slots: slots(start)}
				byType[c.Honeypot] = t
			}
			t.N += c.Count
			t.Slots[i].N += c.Count
		}
	}
	for _, t := range byType {
		a.Types = append(a.Types, *t)
	}
	a.Honeypots = len(a.Types)
	sort.Slice(a.Types, func(i, j int) bool {
		if a.Types[i].N != a.Types[j].N {
			return a.Types[i].N > a.Types[j].N
		}
		return a.Types[i].Type < a.Types[j].Type
	})
	if len(a.Types) > pulseTypes {
		a.Types = a.Types[:pulseTypes]
	}
	return a
}

func (s *Server) handlePulse(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	name := r.URL.Query().Get("range")
	if name == "" {
		name = "24h"
	}
	pr, ok := pulseRanges[name]
	if !ok {
		s.sendAPIError(w, http.StatusBadRequest, "", "Bad range: use 24h, 1h or 1m.")
		return
	}
	if s.db() == nil {
		s.sendAPIError(w, http.StatusServiceUnavailable, "QP-INST-005", "The database is not available.")
		return
	}
	sc, ok := s.db().(database.SlotCounter)
	if !ok {
		s.sendAPIError(w, http.StatusNotImplemented, "", "This database cannot count the timeline.")
		return
	}

	c := &s.api.pulse
	c.mu.Lock()
	defer c.mu.Unlock()
	if hit, ok := c.last[name]; ok && time.Since(hit.at) < pulseReuse {
		writeJSON(w, http.StatusOK, hit.ans)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	now := time.Now()
	start := pulseWindow(now, pr)
	counts, err := sc.CountSlots(ctx, database.SlotQuery{From: start.Add(-time.Duration(pr.points) * pr.step), Step: pr.step, Slots: 2 * pr.points})
	if err != nil {
		s.sendInternalError(w, "pulse: count slots", err)
		return
	}
	a := buildPulse(name, pr, start, counts)
	if st, err := s.db().GetStats(ctx, start); err != nil {
		s.sendInternalError(w, "pulse: stats", err)
		return
	} else if st != nil {
		a.Sources = st.UniqueIPs
	}
	if evs, err := s.db().GetEvents(ctx, database.EventFilter{StartTime: start, Limit: 1}); err == nil && len(evs) > 0 {
		a.Latest = evs[0].Timestamp.UnixMilli()
	}
	top, err := s.db().GetTopAttackers(ctx, pulseSources, start)
	if err != nil {
		s.sendInternalError(w, "pulse: top sources", err)
		return
	}
	for _, t := range top {
		country := t.Country
		if g, ok := geo.Lookup(t.Country); ok {
			country = g.Name
		}
		// QPot has no reputation feed: rep stays empty.
		a.TopSources = append(a.TopSources, pulseSource{IP: t.SourceIP, N: t.AttackCount, Country: country})
	}
	if c.last == nil {
		c.last = map[string]pulseCached{}
	}
	c.last[name] = pulseCached{at: now, ans: a}
	writeJSON(w, http.StatusOK, a)
}
