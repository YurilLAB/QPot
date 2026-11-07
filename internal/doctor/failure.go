package doctor

import (
	"fmt"
	"strings"

	"github.com/qpot/qpot/internal/hostsetup"
)

// Failure returns the error a run of checks ends with, or nil when none
// failed. It carries the first failed check's code, and that code's own Why
// and Fix, so the message never mixes two checks. When several checks
// failed, its details list each one's code on a line of its own.
func Failure(groups ...[]Check) *hostsetup.Error {
	var failed []Check
	for _, g := range groups {
		for _, c := range g {
			if c.Level == "fail" {
				failed = append(failed, c)
			}
		}
	}
	if len(failed) == 0 {
		return nil
	}
	e := hostsetup.E(failCode(failed[0]))
	if len(failed) > 1 {
		var b strings.Builder
		fmt.Fprintf(&b, "%d checks failed; the first is described above. Each one:", len(failed))
		for _, c := range failed {
			fmt.Fprintf(&b, "\n%-14s %s: %s", failCode(c), c.Name, c.Detail)
		}
		e.WithDetails("%s", b.String())
	}
	return e
}

// failCode is a failed check's code; a check that failed without one is a
// bug in QPot.
func failCode(c Check) string {
	if code, ok := hostsetup.Lookup(c.Code); c.Code != "" && ok {
		return code.ID
	}
	return "QP-BUG-001"
}
