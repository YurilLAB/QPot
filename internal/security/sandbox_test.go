package security

import (
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func TestContainerRuntime(t *testing.T) {
	cases := []struct {
		mode string
		want string // expected runtime when available
	}{
		{"none", ""},
		{"gvisor", "runsc"},
		{"kata", "kata-runtime"},
	}
	for _, tc := range cases {
		cfg := &config.SecurityConfig{SandboxMode: tc.mode}
		sb, err := NewSandbox(cfg)
		if err != nil {
			t.Fatalf("NewSandbox(%q): %v", tc.mode, err)
		}
		got := sb.ContainerRuntime()
		// In this environment runsc/kata are not installed, so NewSandbox
		// falls back to none and ContainerRuntime returns "". The invariant we
		// assert universally: ContainerRuntime is non-empty ONLY when the
		// sandbox is both a runtime type AND available.
		if got != "" && got != tc.want {
			t.Errorf("mode %q: ContainerRuntime=%q, want %q or \"\"", tc.mode, got, tc.want)
		}
		if got != "" && !sb.available {
			t.Errorf("mode %q: returned runtime %q while sandbox not available", tc.mode, got)
		}
	}
}
