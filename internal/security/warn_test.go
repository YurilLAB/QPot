package security

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Only explicit, permitted fallback produces a warning. Repeated resolutions
// keep the warning bounded without changing the requested runtime.
func TestFallbackWarningPrintedOnce(t *testing.T) {
	warnMu.Lock()
	previousWarnings := warned
	warned = map[string]bool{}
	warnMu.Unlock()
	defer func() { warnMu.Lock(); warned = previousWarnings; warnMu.Unlock() }()
	var buf bytes.Buffer
	previousOutput := SetWarningOutput(&buf)
	defer SetWarningOutput(previousOutput)
	runtimeRegistryForTest(t, func(context.Context) (map[string]json.RawMessage, error) {
		return map[string]json.RawMessage{"runc": nil}, nil
	})
	sb := sandboxForTest(t, "gvisor", "docker")
	for range 3 {
		selection, err := sb.ResolveForStart(t.Context(), false)
		if err != nil || !selection.Fallback {
			t.Fatalf("explicit fallback: %+v %v", selection, err)
		}
	}
	if n := strings.Count(buf.String(), "explicit sandbox_fallback=docker"); n != 1 {
		t.Fatalf("warning printed %d times: %s", n, buf.String())
	}
	if sb.ContainerRuntime() != "runsc" {
		t.Fatal("warning path changed the declared runtime")
	}
}
