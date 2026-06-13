// Package ypanel implements QPot's phone-home agent to the ypanel operator
// console. ypanel (Yuril Security's unified control panel) never talks to a QPot
// host directly; instead this agent pushes status snapshots to the DireC
// activation worker (the "operator plane") and polls it for allow-listed control
// jobs, which it applies locally. See docs/ypanel.md for the full model.
//
// Wire contract (instance plane on the worker):
//
//	POST /v1/ypanel/push       a status snapshot, on a heartbeat
//	GET  /v1/ypanel/jobs       poll allow-listed control jobs (honeypot enable/disable)
//	POST /v1/ypanel/jobs/ack   report each job's result
//
// Auth on every call:
//
//		Authorization: Bearer DIREC-YPANEL <license_jws> <enroll_token>
//
//	  - license_jws  — the Ed25519 JWS cached by Yuril/DireC activation. The agent
//	    READS it; it never signs (the private key stays on the worker).
//	  - enroll_token — minted ONCE by the operator in the panel and provisioned on
//	    the host (config ypanel.enroll_token).
//
// The per-instance QPot-ID is the LOCAL API secret and is never part of this
// contract: it never reaches the worker or the panel.
package ypanel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

// Version is the agent's self-reported version, surfaced in the User-Agent and
// available for the snapshot. It is intentionally distinct from QPot's build
// version (which is what the snapshot's "version" field carries).
const Version = "1.0.0"

// wellKnownJWSPaths are the activation-cache locations the agent probes for the
// license JWS when no explicit path is configured. The product daemon (DireC /
// the Yuril suite) writes the cached JWS here after activation/heartbeat.
var wellKnownJWSPaths = []string{
	`C:\ProgramData\DireC\license.dat`,
	`C:\ProgramData\Yuril\license.dat`,
	"/etc/direc/license.dat",
	"/etc/yuril/license.dat",
	"/var/lib/direc/license.dat",
}

// Agent is the phone-home reporter. It reads QPot's live state in-process (no
// loopback to the local HTTP API) and applies control jobs straight through the
// instance manager, so it reports full fidelity and actually toggles honeypots.
type Agent struct {
	cfg     *config.Config
	manager *instance.Manager
	cluster *cluster.Manager
	// database is opened best-effort for events/stats; nil-tolerant everywhere.
	database database.Database
	version  string // QPot build version → snapshot "version" field

	jws   string // resolved license JWS
	http  *http.Client
	log   func(string, ...any)
	ready bool
}

// New constructs the agent from config. It returns (nil, nil) when the
// integration is disabled, so callers can `if a != nil { go a.Run(ctx) }`. A
// non-nil agent may still be "not enrolled" (missing credentials): Run reports
// that honestly and idles rather than erroring out `qpot up`.
func New(cfg *config.Config, mgr *instance.Manager, version string) (*Agent, error) {
	if cfg == nil || !cfg.Ypanel.Enabled {
		return nil, nil
	}
	if mgr == nil {
		return nil, fmt.Errorf("ypanel: instance manager is required")
	}

	a := &Agent{
		cfg:     cfg,
		manager: mgr,
		version: version,
		http:    &http.Client{Timeout: 15 * time.Second},
		log: func(format string, args ...any) {
			slog.Info("ypanel-agent: " + fmt.Sprintf(format, args...))
		},
	}

	// Cluster identity is optional; a missing/standalone cluster just means no
	// clusterId/clusterName in the snapshot.
	cm := cluster.NewManager(cfg.DataPath)
	if c, err := cm.LoadCluster(); err == nil && c != nil {
		a.cluster = cm
	}

	// Resolve the license JWS now so readiness is known up front.
	if jws, err := ResolveLicenseJWS(cfg.Ypanel); err == nil {
		a.jws = jws
	} else {
		a.log("license JWS not resolved: %v", err)
	}

	a.ready = a.cfg.Ypanel.InstanceID != "" && a.cfg.Ypanel.EnrollToken != "" &&
		a.jws != "" && strings.TrimSpace(a.cfg.Ypanel.Base) != ""

	// Open the DB best-effort for the events/stats portions of the snapshot.
	// A failure is non-fatal: the agent still reports host + honeypot state.
	if db, err := database.New(&cfg.Database); err != nil {
		a.log("database unavailable for snapshots (events/stats will be empty): %v", err)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := db.Connect(ctx); err != nil {
			a.log("database connect failed (events/stats will be empty): %v", err)
		} else {
			a.database = db
		}
		cancel()
	}

	return a, nil
}

// ResolveLicenseJWS returns the license JWS from, in order: the inline config
// value, the configured path, then the well-known activation-cache paths. It
// returns an error only when none of these yields a non-empty value.
func ResolveLicenseJWS(c config.YpanelConfig) (string, error) {
	if v := strings.TrimSpace(c.LicenseJWS); v != "" {
		return v, nil
	}
	if p := strings.TrimSpace(c.LicenseJWSPath); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("reading ypanel.license_jws_path %q: %w", p, err)
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("ypanel.license_jws_path %q is empty", p)
	}
	for _, p := range wellKnownJWSPaths {
		if b, err := os.ReadFile(p); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v, nil
			}
		}
	}
	return "", errors.New("no license JWS found (set ypanel.license_jws / ypanel.license_jws_path, or activate the Yuril/DireC daemon)")
}

// Ready reports whether the agent has everything it needs to reach the worker.
func (a *Agent) Ready() bool { return a != nil && a.ready }

// Close releases the agent's database handle, if any.
func (a *Agent) Close() {
	if a != nil && a.database != nil {
		_ = a.database.Close()
	}
}

// Run drives the phone-home loop until ctx is cancelled. If the agent is not
// fully enrolled it logs a clear message and returns nil (so `qpot up` keeps
// running and the operator can finish enrolment, then restart).
func (a *Agent) Run(ctx context.Context) error {
	defer a.Close()

	if !a.ready {
		a.log("enabled but not enrolled — set instance_id, enroll_token and a license JWS " +
			"(run 'qpot ypanel setup'); the agent is idle until then")
		return nil
	}

	push := clampDur(a.cfg.Ypanel.PushInterval, 5*time.Second, time.Hour)
	jobs := clampDur(a.cfg.Ypanel.JobsInterval, 5*time.Second, time.Hour)
	a.log("starting: instance=%s base=%s push=%s jobs=%s",
		a.cfg.Ypanel.InstanceID, a.cfg.Ypanel.Base, push, jobs)

	// Push + poll once immediately so the panel lights up without a full cycle.
	a.pushOnce(ctx)
	a.pollOnce(ctx)

	pushTick := time.NewTicker(push)
	jobsTick := time.NewTicker(jobs)
	defer pushTick.Stop()
	defer jobsTick.Stop()

	for {
		select {
		case <-ctx.Done():
			a.log("stopping")
			return nil
		case <-pushTick.C:
			a.pushOnce(ctx)
		case <-jobsTick.C:
			a.pollOnce(ctx)
		}
	}
}

// PushOnce builds and sends a single snapshot, returning the HTTP status and any
// transport error. Exposed for `qpot ypanel test`.
func (a *Agent) PushOnce(ctx context.Context) (int, error) {
	snap := a.buildSnapshot(ctx)
	body, err := json.Marshal(snap)
	if err != nil {
		return 0, fmt.Errorf("marshal snapshot: %w", err)
	}
	var resp workerResp
	status, err := a.call(ctx, http.MethodPost, a.url("/push"), body, &resp)
	if err != nil {
		return status, err
	}
	if status != http.StatusOK || !(resp.OK || resp.Status == "ok") {
		return status, fmt.Errorf("push rejected: HTTP %d code=%s detail=%s", status, resp.Code, resp.Detail)
	}
	return status, nil
}

func (a *Agent) pushOnce(ctx context.Context) {
	status, err := a.PushOnce(ctx)
	switch {
	case err != nil:
		a.log("push error: %v", err)
	default:
		a.log("push ok (HTTP %d)", status)
	}
}

// job is one queued control job as the worker returns it.
type job struct {
	JobID  string `json:"job_id"`
	Verb   string `json:"verb"`
	Target string `json:"target"`
}

func (a *Agent) pollOnce(ctx context.Context) {
	var resp struct {
		OK   bool   `json:"ok"`
		Jobs []job  `json:"jobs"`
		Code string `json:"code"`
	}
	status, err := a.call(ctx, http.MethodGet,
		a.url("/jobs?instance="+a.cfg.Ypanel.InstanceID), nil, &resp)
	if err != nil {
		a.log("jobs poll error: %v", err)
		return
	}
	if status != http.StatusOK {
		a.log("jobs poll: HTTP %d code=%s", status, resp.Code)
		return
	}
	for _, j := range resp.Jobs {
		ok, result := a.applyJob(ctx, j)
		a.ackJob(ctx, j, ok, result)
	}
}

// applyJob applies an allow-listed control job to QPot locally via the instance
// manager — the same path the WebUI's POST /api/honeypots uses — and reports the
// real result. Anything outside the allow-list, or an unknown honeypot target,
// is refused (defence in depth; the worker enforces the verb allow-list too).
func (a *Agent) applyJob(ctx context.Context, j job) (bool, string) {
	switch j.Verb {
	case "honeypot.enable", "honeypot.disable":
	default:
		a.log("job %s: refusing unsupported verb %q", j.JobID, j.Verb)
		return false, "verb not supported by qpot"
	}

	name := strings.TrimSpace(j.Target)
	if _, ok := a.cfg.GetHoneypotConfig(name); !ok {
		a.log("job %s: unknown honeypot target %q", j.JobID, name)
		return false, "unknown honeypot: " + name
	}

	enable := j.Verb == "honeypot.enable"
	if enable {
		a.cfg.EnableHoneypot(name)
		if err := a.manager.StartHoneypot(ctx, name); err != nil {
			a.log("job %s: start %s failed: %v", j.JobID, name, err)
			return false, "start failed: " + err.Error()
		}
	} else {
		a.cfg.DisableHoneypot(name)
		if err := a.manager.StopHoneypot(ctx, name); err != nil {
			a.log("job %s: stop %s failed: %v", j.JobID, name, err)
			return false, "stop failed: " + err.Error()
		}
	}
	if err := config.Save(a.cfg); err != nil {
		// The container action already happened; surface the persistence failure
		// so the next `qpot up` doesn't silently revert the toggle.
		a.log("job %s: applied but config save failed: %v", j.JobID, err)
		return false, "applied but not persisted: " + err.Error()
	}

	a.log("job %s: %s %s applied", j.JobID, j.Verb, name)
	if enable {
		return true, name + " enabled"
	}
	return true, name + " disabled"
}

func (a *Agent) ackJob(ctx context.Context, j job, ok bool, result string) {
	body, _ := json.Marshal(map[string]any{
		"instance_id": a.cfg.Ypanel.InstanceID,
		"job_id":      j.JobID,
		"ok":          ok,
		"result":      clampStr(result, 256),
	})
	status, err := a.call(ctx, http.MethodPost, a.url("/jobs/ack"), body, nil)
	if err != nil || status != http.StatusOK {
		a.log("ack %s failed: HTTP %d err=%v", j.JobID, status, err)
	}
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

type workerResp struct {
	OK     bool   `json:"ok"`
	Status string `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// url builds an instance-plane URL. QPot's instance plane is the bare
// /v1/ypanel/{push,jobs,jobs/ack} (the other products are namespaced).
func (a *Agent) url(suffix string) string {
	return strings.TrimRight(a.cfg.Ypanel.Base, "/") + "/v1/ypanel" + suffix
}

func (a *Agent) call(ctx context.Context, method, url string, body []byte, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, err
	}
	// Secrets ride ONLY in this header — never in the URL or logs.
	req.Header.Set("Authorization", "Bearer DIREC-YPANEL "+a.jws+" "+a.cfg.Ypanel.EnrollToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qpot-ypanel-agent/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out) // best-effort; tolerate non-JSON error bodies
	}
	return resp.StatusCode, nil
}

func clampDur(v, lo, hi time.Duration) time.Duration {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
