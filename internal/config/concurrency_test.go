package config

import (
	"sync"
	"testing"
)

// TestHoneypotsConcurrentAccess is the regression guard for the process-crashing
// data race where the web server mutated Config.Honeypots (POST /api/honeypots
// -> EnableHoneypot/DisableHoneypot) while other request goroutines ranged the
// same map (GET handlers, Status, Save's marshal). Before the RWMutex fix this
// reliably aborts the whole process with the runtime's unrecoverable
// "fatal error: concurrent map read and map write" (which `-race` also flags).
// The accessors (GetHoneypotConfig / SnapshotHoneypots) must make it safe.
func TestHoneypotsConcurrentAccess(t *testing.T) {
	c := &Config{Honeypots: map[string]HoneypotConfig{
		"cowrie":    {Enabled: true, Port: 22},
		"ssh-proxy": {Enabled: false, Port: 22},
		"conpot":    {Enabled: false, Port: 102},
	}}

	const workers = 16
	const iters = 2000
	var wg sync.WaitGroup
	wg.Add(workers * 3)

	for i := 0; i < workers; i++ {
		// Writers: flip enable/disable.
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if j%2 == 0 {
					c.EnableHoneypot("ssh-proxy")
				} else {
					c.DisableHoneypot("ssh-proxy")
				}
			}
		}()
		// Readers: single-key.
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_, _ = c.GetHoneypotConfig("ssh-proxy")
			}
		}()
		// Readers: full snapshot (the GET / Status path).
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				for name, hp := range c.SnapshotHoneypots() {
					_ = name
					_ = hp.Enabled
				}
			}
		}()
	}
	wg.Wait()

	// Sanity: the snapshot is a copy — mutating it must not affect the source.
	snap := c.SnapshotHoneypots()
	snap["cowrie"] = HoneypotConfig{Enabled: false}
	if hp, _ := c.GetHoneypotConfig("cowrie"); !hp.Enabled {
		t.Error("SnapshotHoneypots must return a copy; mutating it changed the source")
	}
}
