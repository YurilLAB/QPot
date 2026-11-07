package doctor

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/hostsetup"
)

func TestFailure(t *testing.T) {
	ok := Check{Name: "docker", Level: "ok", Detail: "installed"}
	warn := Check{Name: "memory", Level: "warn", Detail: "low", Code: "QP-RES-001"}
	docker := Check{Name: "docker", Level: "fail", Detail: "not installed", Code: "QP-DOCKER-001"}
	stopped := Check{Name: "containers", Level: "fail", Detail: "not running (qpot up -d -i x)", Code: "QP-INST-007"}

	if e := Failure([]Check{ok, warn}, nil); e != nil {
		t.Fatalf("no failed check, error %v", e)
	}

	e := Failure([]Check{ok}, []Check{stopped})
	if e == nil || e.Code != "QP-INST-007" || e.Cause() != e.Entry().Cause || e.Remedy() != e.Entry().Fix || e.Details != "" {
		t.Fatalf("one failure: %+v", e)
	}

	// Two failures in different groups: the first one's code, Why and Fix;
	// each failed check's code on a line of its own.
	e = Failure([]Check{ok, docker, warn}, []Check{stopped})
	want := hostsetup.E("QP-DOCKER-001").Entry()
	if e == nil || e.Code != want.ID || e.Cause() != want.Cause || e.Remedy() != want.Fix {
		t.Fatalf("two failures: %+v", e)
	}
	lines := strings.Split(e.Details, "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "2 checks failed") ||
		!strings.HasPrefix(lines[1], "QP-DOCKER-001") || !strings.Contains(lines[1], "docker: not installed") ||
		!strings.HasPrefix(lines[2], "QP-INST-007") || !strings.Contains(lines[2], "containers: not running") {
		t.Fatalf("details: %q", e.Details)
	}
	if strings.Contains(e.Details, "QP-RES-001") {
		t.Fatalf("a warning is listed as failed: %q", e.Details)
	}

	// A failed check without a code, or with one QPot does not have, is a bug.
	for _, code := range []string{"", "QP-NOPE-999", "not a code"} {
		if e := Failure([]Check{{Name: "x", Level: "fail", Code: code}}); e == nil || e.Code != "QP-BUG-001" {
			t.Fatalf("code %q: %+v", code, e)
		}
	}
	if e := Failure([]Check{{Name: "x", Level: "fail", Code: "qp-docker-1"}}); e == nil || e.Code != "QP-DOCKER-001" {
		t.Fatalf("loosely written code: %+v", e)
	}
}
