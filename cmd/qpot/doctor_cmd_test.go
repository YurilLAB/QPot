package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/hostsetup"
)

// With several failed checks, qpot doctor's final error names the first
// one, and its Why and Fix are that check's, not another's: on a host
// without Docker whose instance is stopped it once said "Docker is not
// installed. Why: Instance ... is not running."
func TestDoctorErrorBelongsToOneCheck(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	if err := runInstance("create", "dtest"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir()) // no docker

	var out bytes.Buffer
	e := hostsetup.AsError(runDoctor(context.Background(), &out, "dtest"))
	if e == nil {
		t.Fatalf("doctor passed without Docker:\n%s", out.String())
	}
	entry := e.Entry()
	if e.Code != "QP-DOCKER-001" || e.Cause() != entry.Cause || e.Remedy() != entry.Fix {
		t.Fatalf("error %s: Why %q, Fix %q; want QP-DOCKER-001's own %q, %q", e.Code, e.Cause(), e.Remedy(), entry.Cause, entry.Fix)
	}
	// The other failed check is listed by its code, each on its own line.
	lines := strings.Split(e.Details, "\n")
	var docker, inst bool
	for _, l := range lines {
		docker = docker || strings.Contains(l, "QP-DOCKER-001") && !strings.Contains(l, "QP-INST-007")
		inst = inst || strings.Contains(l, "QP-INST-007") && strings.Contains(l, "-i dtest") && !strings.Contains(l, "QP-DOCKER-001")
	}
	if !docker || !inst || !strings.Contains(e.Details, "2 checks failed") {
		t.Fatalf("details do not list each failed check: %q", e.Details)
	}

	var printed bytes.Buffer
	printSetupError(&printed, e)
	for _, l := range strings.Split(printed.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "Why:") && strings.Contains(l, "not running") {
			t.Fatalf("the Why of the Docker error talks about the instance:\n%s", printed.String())
		}
	}
}

// A stopped instance that is the only failure names the instance and the
// command that starts it; with a host failure too, the host check's own Why
// and Fix stay.
func TestDoctorStoppedInstanceError(t *testing.T) {
	ok := check{Name: "docker", Level: "ok", Detail: "installed"}
	docker := check{Name: "docker", Level: "fail", Detail: "not installed", Code: "QP-DOCKER-001"}
	for _, tc := range []struct {
		inst, fix string
	}{{"dtest", "Start it with: qpot up -d -i dtest"}, {"default", "Start it with: qpot up -d"}} {
		stopped := []check{{Name: "containers", Level: "fail", Detail: "not running", Code: "QP-INST-007"}}
		e := stoppedInstanceError(tc.inst, false, []check{ok}, stopped)
		if e.Code != "QP-INST-007" || e.Cause() != `Instance "`+tc.inst+`" is not running.` || e.Remedy() != tc.fix || e.Details != "" {
			t.Fatalf("%s: %s Why %q Fix %q Details %q", tc.inst, e.Code, e.Cause(), e.Remedy(), e.Details)
		}
		e = stoppedInstanceError(tc.inst, true, []check{docker}, stopped)
		entry := e.Entry()
		if e.Code != "QP-DOCKER-001" || e.Cause() != entry.Cause || e.Remedy() != entry.Fix {
			t.Fatalf("%s with no docker: %s Why %q Fix %q", tc.inst, e.Code, e.Cause(), e.Remedy())
		}
	}
}
