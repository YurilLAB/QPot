package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/doctor"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

// doctorServer is an API test server whose doctor checks are canned; runs
// counts how often they ran.
func doctorServer(t *testing.T, host, inst []doctor.Check) (*apiTestServer, *atomic.Int32) {
	t.Helper()
	a := newAPITestServer(t, "api-doctor", func(c *config.Config) { c.Database.Password = "dbpw-" + strings.Repeat("q", 12) })
	var runs atomic.Int32
	a.s.api.doctor = doctorChecks{
		host: func(context.Context) []doctor.Check { runs.Add(1); return host },
		instance: func(_ context.Context, cfg *config.Config) []doctor.Check {
			if cfg.InstanceName != "api-doctor" {
				t.Errorf("instance checks got config %q", cfg.InstanceName)
			}
			return inst
		},
	}
	return a, &runs
}

func getDoctor(t *testing.T, a *apiTestServer) doctorReport {
	t.Helper()
	rec := a.do(http.MethodGet, "/api/doctor", "")
	var rep doctorReport
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil {
		t.Fatalf("GET /api/doctor: %d %s", rec.Code, rec.Body.String())
	}
	return rep
}

func TestDoctorReport(t *testing.T) {
	host := []doctor.Check{
		{Name: "docker", Level: "ok", Detail: "installed"},
		{Name: "memory", Level: "warn", Detail: "1.5 GiB", Code: "QP-RES-001"},
	}
	inst := []doctor.Check{
		{Name: "database", Level: "ok", Detail: "running (healthy)"},
		{Name: "honeypot cowrie", Level: "fail", Detail: "exited", Code: "QP-INST-008"},
		{Name: "database schema", Level: "fail", Detail: "not ready: auth failed for qpot:dbpw-" + strings.Repeat("q", 12), Code: "QP-INST-005"},
	}
	a, runs := doctorServer(t, host, inst)
	assertAuthRequired(t, a.h, http.MethodGet, "/api/doctor", "")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := a.do(m, "/api/doctor", `{}`); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/doctor: %d, want 405 (read-only)", m, rec.Code)
		}
	}
	if runs.Load() != 0 {
		t.Fatal("a refused request ran the checks")
	}

	rep := getDoctor(t, a)
	if rep.OK || rep.Cached || rep.FirstFailCode != "QP-INST-008" || len(rep.Checks) != 5 || rep.RanAt.IsZero() {
		t.Fatalf("report: %+v", rep)
	}
	want := hostsetup.E("QP-INST-008").Entry()
	if f := rep.Failure; f == nil || f.Code != want.ID || f.Title != want.Title || f.Cause != want.Cause || f.Fix != want.Fix {
		t.Fatalf("failure: %+v", rep.Failure)
	}
	if c := rep.Checks[0]; c.Section != "host" || c.Name != "docker" || c.Level != "ok" || c.Code != "" || c.Title != "" {
		t.Errorf("check 0: %+v", c)
	}
	if c := rep.Checks[1]; c.Section != "host" || c.Code != "QP-RES-001" || c.Title == "" {
		t.Errorf("check 1: %+v", c)
	}
	if c := rep.Checks[3]; c.Section != "instance" || c.Level != "fail" || c.Title != want.Title {
		t.Errorf("check 3: %+v", c)
	}
	if d := rep.Checks[4].Detail; strings.Contains(d, "dbpw-") || !strings.Contains(d, "[hidden]") {
		t.Errorf("the database password reached a check: %q", d)
	}

	// Reused for a while, then run again.
	if again := getDoctor(t, a); !again.Cached || runs.Load() != 1 || !again.RanAt.Equal(rep.RanAt) {
		t.Fatalf("second report: cached %v, runs %d", again.Cached, runs.Load())
	}
	a.s.api.doctorMu.Lock()
	a.s.api.doctorLast.RanAt = time.Now().Add(-doctorReuse - time.Second)
	a.s.api.doctorMu.Unlock()
	if fresh := getDoctor(t, a); fresh.Cached || runs.Load() != 2 {
		t.Fatalf("after the reuse window: cached %v, runs %d", fresh.Cached, runs.Load())
	}
}

// Everything passing: ok, no failure; a failed check without a code (or with
// one QPot does not have) is QPot's bug, as in qpot doctor.
func TestDoctorReportPassAndUnknownCode(t *testing.T) {
	a, _ := doctorServer(t, []doctor.Check{{Name: "docker", Level: "ok"}}, []doctor.Check{{Name: "web UI", Level: "ok"}})
	if rep := getDoctor(t, a); !rep.OK || rep.Failure != nil || rep.FirstFailCode != "" || len(rep.Checks) != 2 {
		t.Fatalf("passing report: %+v", rep)
	}
	b, _ := doctorServer(t, nil, []doctor.Check{{Name: "odd", Level: "fail", Code: "QP-NOPE-999"}})
	if rep := getDoctor(t, b); rep.OK || rep.FirstFailCode != "QP-BUG-001" || rep.Checks[0].Code != "" {
		t.Fatalf("unknown code: %+v", rep)
	}
}

// Requests that arrive together run the checks once.
func TestDoctorRunsOneAtATime(t *testing.T) {
	a, runs := doctorServer(t, []doctor.Check{{Name: "docker", Level: "ok"}}, nil)
	slow := a.s.api.doctor.host
	var inFlight, most atomic.Int32
	a.s.api.doctor.host = func(ctx context.Context) []doctor.Check {
		n := inFlight.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		inFlight.Add(-1)
		return slow(ctx)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := a.do(http.MethodGet, "/api/doctor", ""); rec.Code != http.StatusOK {
				t.Errorf("GET: %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	if runs.Load() != 1 || most.Load() != 1 {
		t.Fatalf("runs %d, at most %d at once", runs.Load(), most.Load())
	}
}

func TestDoctorExplain(t *testing.T) {
	a := newAPITestServer(t, "api-explain", nil)
	assertAuthRequired(t, a.h, http.MethodGet, "/api/doctor/explain?code=QP-PKG-001", "")
	want := hostsetup.E("QP-PKG-001").Entry()
	for _, q := range []string{"QP-PKG-001", "qp-pkg-1", "PKG%20001"} {
		rec := a.do(http.MethodGet, "/api/doctor/explain?code="+q, "")
		var e codeEntry
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &e) != nil {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body.String())
		}
		if e.Code != want.ID || e.Title != want.Title || e.Cause != want.Cause || e.Fix != want.Fix ||
			e.Category != "PKG" || e.CategoryName == "" || e.ExitStatus != hostsetup.ExitStatus(want.ID) {
			t.Fatalf("%s: %+v", q, e)
		}
	}
	for _, q := range []string{"QP-NOPE-001", "%3Cscript%3E", strings.Repeat("A", 5000)} {
		rec := a.do(http.MethodGet, "/api/doctor/explain?code="+q, "")
		if e := decodeAPIError(t, rec); rec.Code != http.StatusNotFound || e.Code != "QP-INPUT-011" || strings.Contains(e.Error, "script") || strings.Contains(e.Error, "NOPE") {
			t.Errorf("%.20s: %d %+v", q, rec.Code, e)
		}
	}
	if rec := a.do(http.MethodGet, "/api/doctor/explain", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("no code: %d", rec.Code)
	}
}

func TestDoctorCodes(t *testing.T) {
	a := newAPITestServer(t, "api-codes", nil)
	assertAuthRequired(t, a.h, http.MethodGet, "/api/doctor/codes", "")
	rec := a.do(http.MethodGet, "/api/doctor/codes", "")
	var out struct {
		Categories []codeCategory `json:"categories"`
		Codes      []codeEntry    `json:"codes"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(out.Codes) != len(hostsetup.Codes()) || len(out.Categories) != len(hostsetup.Categories()) {
		t.Fatalf("%d codes, %d categories", len(out.Codes), len(out.Categories))
	}
	cats := map[string]bool{}
	for _, c := range out.Categories {
		cats[c.Key] = c.Name != "" && c.ExitStatus > 0
	}
	for _, c := range out.Codes {
		if !cats[c.Category] || c.Title == "" || c.Fix == "" || !strings.HasPrefix(c.Code, "QP-"+c.Category+"-") {
			t.Errorf("code %+v", c)
		}
	}
}

// The secrets a check's detail can carry are hidden, longest first (so a
// secret that contains another is hidden whole).
func TestConfigSecretsScrub(t *testing.T) {
	cfg := config.Default("scrub")
	cfg.QPotID = validTestID
	cfg.Database.Password = "pw-" + strings.Repeat("x", 10)
	cfg.WebUI.Password = cfg.Database.Password + "-longer"
	cfg.Alerts.WebhookURL = "https://hooks.example.net/" + strings.Repeat("t", 10)
	cfg.EnableHoneypot("galah")
	cfg.SetHoneypotCustomConfig("galah", map[string]string{"llm_api_key": "key-" + strings.Repeat("k", 10), "llm_model": "abc"})
	secrets := configSecrets(cfg)
	in := strings.Join([]string{cfg.QPotID, cfg.Database.Password, cfg.WebUI.Password, cfg.Alerts.WebhookURL, "key-" + strings.Repeat("k", 10), "abc"}, " ")
	if got := scrub(in, secrets); got != "[hidden] [hidden] [hidden] [hidden] [hidden] abc" {
		t.Fatalf("scrub: %q", got)
	}
}

// With failures in both sections the host's comes first, as in qpot doctor.
func TestDoctorFirstFailureIsTheHosts(t *testing.T) {
	a, _ := doctorServer(t,
		[]doctor.Check{{Name: "docker", Level: "fail", Detail: "not installed", Code: "QP-DOCKER-001"}},
		[]doctor.Check{{Name: "containers", Level: "fail", Detail: "not running", Code: "QP-INST-007"}})
	rep := getDoctor(t, a)
	want := hostsetup.E("QP-DOCKER-001").Entry()
	if rep.FirstFailCode != want.ID || rep.Failure == nil || rep.Failure.Cause != want.Cause {
		t.Fatalf("report: %+v", rep)
	}
}

// The instance checks the API runs: a stopped instance is one failed check
// naming the start command; a running one gets qpot doctor's checks, with
// this server as its control plane.
func TestInstanceDoctorChecks(t *testing.T) {
	a := newAPITestServer(t, "api-doc-inst", func(c *config.Config) {
		c.EnableHoneypot("cowrie")
		c.WebUI.Enabled = false
		c.Database.Host, c.Database.Port = "127.0.0.1", 1
	})
	cfg, err := a.s.readConfig()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	cs := a.s.instanceDoctorChecks(ctx, cfg)
	if len(cs) != 1 || cs[0].Level != "fail" || cs[0].Code != "QP-INST-007" || !strings.Contains(cs[0].Detail, "qpot up -d -i api-doc-inst") {
		t.Fatalf("stopped: %+v", cs)
	}

	a.runner.running = true
	a.runner.states = map[string]instance.ServiceState{"database": {State: "running", Health: "healthy"}, "collector": {State: "running"}, "cowrie": {State: "exited"}}
	cs = a.s.instanceDoctorChecks(ctx, cfg)
	got := map[string]doctor.Check{}
	for _, c := range cs {
		got[c.Name] = c
	}
	if got["database"].Level != "ok" || got["honeypot cowrie"].Code != "QP-INST-008" || got["database schema"].Code != "QP-INST-005" {
		t.Fatalf("running: %+v", cs)
	}
	if cp := got["control plane"]; cp.Level != "ok" || !strings.Contains(cp.Detail, fmt.Sprint(os.Getpid())) {
		t.Fatalf("control plane: %+v", cp)
	}
	if _, ok := got["web UI"]; ok {
		t.Error("web UI checked although it is off")
	}

	a.s.api.runner = nil // no runner and no manager: the containers cannot be reached
	if cs := a.s.instanceDoctorChecks(ctx, cfg); len(cs) != 1 || cs[0].Code != "QP-INST-007" {
		t.Fatalf("unreachable: %+v", cs)
	}
}

// explainRefusals are the only refusals of GET /api/doctor/explain: fixed
// sentences, so nothing that was sent comes back.
var explainRefusals = map[string]bool{
	"Give an error code, e.g. ?code=QP-PKG-001.":                                true,
	"That is not one of QPot's error codes (GET /api/doctor/codes lists them).": true,
}

// FuzzDoctorExplain: any code gets 200, 400 or 404, never a server error,
// and a refusal is one of the fixed sentences.
func FuzzDoctorExplain(f *testing.F) {
	for _, s := range []string{"QP-PKG-001", "qp-pkg-1", "PKG 001", "", "QP-NOPE-1", "<script>", strings.Repeat("9", 64), "QP-PKG-\x00"} {
		f.Add(s)
	}
	a := newAPITestServer(f, "api-fuzz-explain", nil)
	f.Fuzz(func(t *testing.T, code string) {
		req := httptest.NewRequest(http.MethodGet, "/api/doctor/explain", nil)
		req.URL.RawQuery = url.Values{"code": {code}}.Encode()
		req.Header.Set("X-QPot-ID", validTestID)
		rec := httptest.NewRecorder()
		a.h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			var e codeEntry
			if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || !strings.HasPrefix(e.Code, "QP-") {
				t.Fatalf("%q: %s", code, rec.Body.String())
			}
		case http.StatusBadRequest, http.StatusNotFound:
			var e apiError
			if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || !explainRefusals[e.Error] || e.Code != "QP-INPUT-011" {
				t.Fatalf("%q: %d %s", code, rec.Code, rec.Body.String())
			}
		default:
			t.Fatalf("%q: %d %s", code, rec.Code, rec.Body.String())
		}
	})
}

func TestIndustrialManagementCodesExplain(t *testing.T) {
	a := newAPITestServer(t, "api-coldcodes", nil)
	for _, id := range []string{"QP-WEB-004", "QP-INST-009", "QP-INST-010"} {
		rec := a.do(http.MethodGet, "/api/doctor/explain?code="+id, "")
		var entry codeEntry
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &entry) != nil || entry.Code != id || entry.Title == "" || entry.Cause == "" || entry.Fix == "" {
			t.Fatalf("%s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
}
