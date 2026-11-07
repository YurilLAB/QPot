package server

import (
	"context"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/doctor"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

// GET /api/doctor: `qpot doctor`'s checks, read-only: it never installs,
// starts or changes anything (no `qpot setup`, no `--install-docker`).
// GET /api/doctor/explain?code=: one error code, as `qpot doctor --explain`.
// GET /api/doctor/codes: the whole error code reference.

const (
	// doctorReuse is how long a report is answered again instead of running
	// the checks (each run starts docker and probes ports).
	doctorReuse = 10 * time.Second
	// doctorTimeout bounds one run of the checks.
	doctorTimeout = 90 * time.Second
)

type doctorCheck struct {
	Section string `json:"section"` // "host" or "instance"
	Name    string `json:"name"`
	Level   string `json:"level"` // "ok", "warn", "fail"
	Detail  string `json:"detail"`
	Code    string `json:"code"`
	// Title is the code's one-line title, for a check that has a code.
	Title string `json:"title,omitempty"`
}

// doctorFailure is what `qpot doctor` ends with: the first failed check's
// code with that check's own cause and fix.
type doctorFailure struct {
	Code  string `json:"code"`
	Title string `json:"title"`
	Cause string `json:"cause"`
	Fix   string `json:"fix"`
}

type doctorReport struct {
	OK            bool           `json:"ok"`
	FirstFailCode string         `json:"first_fail_code,omitempty"`
	Failure       *doctorFailure `json:"failure,omitempty"`
	RanAt         time.Time      `json:"ran_at"`
	Cached        bool           `json:"cached"`
	Checks        []doctorCheck  `json:"checks"`
}

// doctorChecks are the check runs of GET /api/doctor (tests replace them).
type doctorChecks struct {
	host     func(ctx context.Context) []doctor.Check
	instance func(ctx context.Context, cfg *config.Config) []doctor.Check
}

// hostDoctorChecks are `qpot doctor`'s host checks: Docker, Compose, memory
// and disk, as the user the server runs as (never with sudo).
func hostDoctorChecks(ctx context.Context) []doctor.Check { return doctor.HostChecks(ctx) }

// instanceDoctorChecks are `qpot doctor`'s instance checks. The control
// plane is this server, so it is running.
func (s *Server) instanceDoctorChecks(ctx context.Context, cfg *config.Config) []doctor.Check {
	runner := s.liveRunner()
	if runner == nil || !runner.IsRunning(ctx) {
		return []doctor.Check{{Name: "containers", Level: "fail",
			Detail: "not running (qpot up -d" + iFlag(cfg.InstanceName) + ")", Code: "QP-INST-007"}}
	}
	st := s.serviceStater()
	if st == nil {
		return []doctor.Check{{Name: "containers", Level: "fail", Detail: "not reachable from the web UI", Code: "QP-INST-007"}}
	}
	return doctor.HealthChecks(ctx, cfg, st, func(*config.Config) int { return os.Getpid() })
}

// iFlag is the -i flag for a command about the instance ("" for default).
func iFlag(name string) string {
	if name == "" || name == "default" {
		return ""
	}
	return " -i " + name
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	cfg, err := s.readConfig()
	if err != nil {
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	// One run at a time: a request that arrives during a run waits for it
	// and gets its report.
	s.api.doctorMu.Lock()
	defer s.api.doctorMu.Unlock()
	if last := s.api.doctorLast; last != nil && time.Since(last.RanAt) < doctorReuse {
		rep := *last
		rep.Cached = true
		writeJSON(w, http.StatusOK, rep)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), doctorTimeout)
	defer cancel()
	checks := s.api.doctor
	if checks.host == nil {
		checks.host = hostDoctorChecks
	}
	if checks.instance == nil {
		checks.instance = s.instanceDoctorChecks
	}
	host := checks.host(ctx)
	inst := checks.instance(ctx, cfg)

	rep := doctorReport{OK: true, RanAt: time.Now().UTC(), Checks: []doctorCheck{}}
	secrets := configSecrets(cfg)
	add := func(section string, cs []doctor.Check) {
		for _, c := range cs {
			dc := doctorCheck{Section: section, Name: scrub(c.Name, secrets), Level: c.Level, Detail: scrub(c.Detail, secrets)}
			if code, ok := hostsetup.Lookup(c.Code); c.Code != "" && ok {
				dc.Code, dc.Title = code.ID, code.Title
			}
			if c.Level == "fail" {
				rep.OK = false
			}
			rep.Checks = append(rep.Checks, dc)
		}
	}
	add("host", host)
	add("instance", inst)
	if e := doctor.Failure(host, inst); e != nil {
		rep.FirstFailCode = e.Code
		rep.Failure = &doctorFailure{Code: e.Code, Title: e.Entry().Title, Cause: scrub(e.Cause(), secrets), Fix: scrub(e.Remedy(), secrets)}
	}
	s.api.doctorLast = &rep
	writeJSON(w, http.StatusOK, rep)
}

// configSecrets are the config's secret values, longest first, so none of
// them can reach an answer through a check's detail (a driver error).
func configSecrets(cfg *config.Config) []string {
	vals := []string{cfg.QPotID, cfg.Database.Password, cfg.WebUI.Password, cfg.Alerts.WebhookURL}
	for _, hp := range cfg.SnapshotHoneypots() {
		for k, v := range hp.CustomConfig {
			if instance.IsSecretSetting(k) {
				vals = append(vals, v)
			}
		}
	}
	var out []string
	for _, v := range vals {
		if len(v) >= 4 {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// scrub hides every secret in s.
func scrub(s string, secrets []string) string {
	for _, v := range secrets {
		s = strings.ReplaceAll(s, v, "[hidden]")
	}
	return s
}

type codeEntry struct {
	Code         string `json:"code"`
	Title        string `json:"title"`
	Cause        string `json:"cause"`
	Fix          string `json:"fix"`
	Category     string `json:"category"`
	CategoryName string `json:"category_name"`
	ExitStatus   int    `json:"exit_status"`
}

func newCodeEntry(c hostsetup.Code) codeEntry {
	cat, _ := hostsetup.CategoryOf(c.Category())
	return codeEntry{Code: c.ID, Title: c.Title, Cause: c.Cause, Fix: c.Fix, Category: cat.Key, CategoryName: cat.Name, ExitStatus: cat.Exit}
}

func (s *Server) handleDoctorExplain(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	q := r.URL.Query().Get("code")
	if q == "" {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-011", "Give an error code, e.g. ?code=QP-PKG-001.")
		return
	}
	c, ok := hostsetup.Lookup(q)
	if !ok {
		// The code is not echoed: it is whatever the caller sent.
		s.sendAPIError(w, http.StatusNotFound, "QP-INPUT-011", "That is not one of QPot's error codes (GET /api/doctor/codes lists them).")
		return
	}
	writeJSON(w, http.StatusOK, newCodeEntry(c))
}

type codeCategory struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	ExitStatus int    `json:"exit_status"`
}

func (s *Server) handleDoctorCodes(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	out := struct {
		Categories []codeCategory `json:"categories"`
		Codes      []codeEntry    `json:"codes"`
	}{Categories: []codeCategory{}, Codes: []codeEntry{}}
	for _, c := range hostsetup.Categories() {
		out.Categories = append(out.Categories, codeCategory{Key: c.Key, Name: c.Name, ExitStatus: c.Exit})
	}
	for _, c := range hostsetup.Codes() {
		out.Codes = append(out.Codes, newCodeEntry(c))
	}
	writeJSON(w, http.StatusOK, out)
}
