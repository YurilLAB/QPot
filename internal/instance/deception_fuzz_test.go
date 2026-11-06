package instance

import (
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// FuzzDeceptionSeed ensures per-instance identity derivation never panics or
// returns an out-of-range selection for any seed (incl. empty / binary).
func FuzzDeceptionSeed(f *testing.F) {
	for _, s := range []string{"", "qp_x", "a", "\x00\xff", "instance-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed string) {
		cfg := config.Default("seed-fuzz")
		cfg.QPotID = seed
		p := cowriePersona(cfg) // must not panic / index out of range
		var server bool
		for _, c := range tpotCowriePersonas {
			if c.ID == p {
				server = c.Server
			}
		}
		if !server {
			t.Errorf("seed %q picked %q, want a server persona", seed, p)
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
