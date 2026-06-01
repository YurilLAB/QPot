package instance

import "testing"

// FuzzDeceptionSeed ensures per-instance identity derivation never panics or
// returns an out-of-range selection for any seed (incl. empty / binary).
func FuzzDeceptionSeed(f *testing.F) {
	for _, s := range []string{"", "qp_x", "a", "\x00\xff", "instance-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed string) {
		p := profileForSeed(seed) // must not panic / index out of range
		if p.SSHVersion == "" {
			t.Errorf("empty SSHVersion for seed %q", seed)
		}
		h := hostnameForSeed(seed)
		if h == "" {
			t.Errorf("empty hostname for seed %q", seed)
		}
		if i := seededIndex(seed, 0); i != 0 {
			t.Errorf("seededIndex with n=0 returned %d, want 0", i)
		}
	})
}
