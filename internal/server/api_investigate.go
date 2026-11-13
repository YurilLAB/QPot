package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/investigate"
)

// The investigation view (doc/investigate.md): what there is to open, the
// case of one session or campaign, and its evidence bundle. All three only
// read.

// caseTimeout bounds the building of one case.
const caseTimeout = 90 * time.Second

// caseSlots is how many cases may be built at once: each reads up to tens of
// thousands of events.
const caseSlots = 2

// reCaseID is what a session ID or campaign fingerprint may look like.
var reCaseID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// GET /api/investigate?limit=N: the most recent sessions and the campaigns
// they form.
func (s *Server) handleInvestigate(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	limit, err := parseIntParam(r.URL.Query(), "limit", investigate.DefaultList, 1, investigate.MaxList)
	if err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "", "Bad request: "+err.Error()+".")
		return
	}
	db := s.db()
	if db == nil {
		s.sendAPIError(w, http.StatusServiceUnavailable, "QP-INST-005", "The database is not available.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), caseTimeout)
	defer cancel()
	listing, err := investigate.List(ctx, db, limit)
	if err != nil {
		s.sendInternalError(w, "investigate: list failed", err)
		return
	}
	writeJSON(w, http.StatusOK, listing)
}

// buildCase answers the request's case, or writes the error and returns nil.
func (s *Server) buildCase(w http.ResponseWriter, r *http.Request) *investigate.Case {
	q := r.URL.Query()
	session, campaign := q.Get("session"), q.Get("campaign")
	if (session == "") == (campaign == "") {
		s.sendAPIError(w, http.StatusBadRequest, "", "Name one session (session=) or one campaign (campaign=).")
		return nil
	}
	if !reCaseID.MatchString(session + campaign) {
		s.sendAPIError(w, http.StatusBadRequest, "", "That is not a session ID or a campaign fingerprint.")
		return nil
	}
	maxEvents, err := parseIntParam(q, "max_events", investigate.DefaultMaxEvents, 1, investigate.HardMaxEvents)
	if err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "", "Bad request: "+err.Error()+".")
		return nil
	}
	db := s.db()
	if db == nil {
		s.sendAPIError(w, http.StatusServiceUnavailable, "QP-INST-005", "The database is not available.")
		return nil
	}
	s.caseMu.Lock()
	busy := s.casesBuilding >= caseSlots
	if !busy {
		s.casesBuilding++
	}
	s.caseMu.Unlock()
	if busy {
		w.Header().Set("Retry-After", "5")
		s.sendAPIError(w, http.StatusTooManyRequests, "", "Other cases are being put together. Try again in a moment.")
		return nil
	}
	defer func() {
		s.caseMu.Lock()
		s.casesBuilding--
		s.caseMu.Unlock()
	}()
	opts := investigate.Options{MaxEvents: maxEvents, Output: instance.SSHCapturedOutput(s.config)}
	if s.canaries != nil {
		opts.Trips = s.canaries.Trips(0)
	} else {
		opts.Trips = []*canary.Trip{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), caseTimeout)
	defer cancel()
	var c *investigate.Case
	if session != "" {
		c, err = investigate.SessionCaseFor(ctx, db, session, opts)
	} else {
		c, err = investigate.CampaignCaseFor(ctx, db, campaign, opts)
	}
	switch {
	case errors.Is(err, investigate.ErrNotFound):
		s.sendAPIError(w, http.StatusNotFound, "", "QPot has no such session or campaign among its most recent "+strconv.Itoa(investigate.SessionScan)+" sessions.")
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		s.sendAPIError(w, http.StatusGatewayTimeout, "", "Reading this case took too long. Ask for fewer events (max_events).")
		return nil
	case err != nil:
		s.sendInternalError(w, "investigate: case failed", err)
		return nil
	}
	c.Instance = s.config.InstanceName
	return c
}

// GET /api/investigate/case?session=ID or ?campaign=FINGERPRINT, with an
// optional max_events: the case.
func (s *Server) handleInvestigateCase(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	if c := s.buildCase(w, r); c != nil {
		writeJSON(w, http.StatusOK, c)
	}
}

// GET /api/investigate/export, with the parameters of the case: the case as
// an evidence bundle (a zip archive with a manifest of hashes).
func (s *Server) handleInvestigateExport(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	c := s.buildCase(w, r)
	if c == nil {
		return
	}
	// Built whole before the first byte is sent, so a failure is an error
	// answer and never half an archive.
	var buf bytes.Buffer
	if _, err := investigate.WriteBundle(&buf, c); err != nil {
		s.sendInternalError(w, "investigate: export failed", err)
		return
	}
	name := "qpot-" + c.Kind + "-" + bundleNameID(c.ID) + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}

// bundleNameID is the start of a case ID, as a file name may hold it.
func bundleNameID(id string) string {
	out := make([]byte, 0, 24)
	for i := 0; i < len(id) && len(out) < 24; i++ {
		if c := id[i]; (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "case"
	}
	return string(out)
}
