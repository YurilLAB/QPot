package security

import (
	"bytes"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// A command that builds several sandboxes (qpot setup builds a manager more
// than once) prints each fallback warning once, where it was told to.
func TestFallbackWarningPrintedOnce(t *testing.T) {
	var buf bytes.Buffer
	prev := SetWarningOutput(&buf)
	defer SetWarningOutput(prev)
	for i := 0; i < 3; i++ {
		if _, err := NewSandbox(&config.SecurityConfig{SandboxMode: "warn-once-test"}); err != nil {
			t.Error(err)
		}
	}
	if n := strings.Count(buf.String(), `unknown sandbox mode "warn-once-test"`); n != 1 {
		t.Fatalf("warning printed %d times:\n%s", n, buf.String())
	}
}
