package config

import "testing"

// FuzzAllocatePortFor ensures the per-honeypot host-port allocator never panics
// and always returns a valid, non-privileged host port for any honeypot name /
// container port, and is deterministic.
func FuzzAllocatePortFor(f *testing.F) {
	f.Add("cowrie", 22)
	f.Add("", 0)
	f.Add("heralding\n; rm", 65535)
	f.Add("a-very-long-honeypot-name-xyz", -1)
	f.Fuzz(func(t *testing.T, honeypot string, port int) {
		c := Default("fuzz")
		c.Ports.AutoAllocate = true
		hp1 := c.AllocatePortFor(honeypot, port)
		hp2 := c.AllocatePortFor(honeypot, port)
		if hp1 != hp2 {
			t.Errorf("AllocatePortFor not deterministic: %d vs %d", hp1, hp2)
		}
		if hp1 <= 1024 || hp1 > 65535 {
			t.Errorf("AllocatePortFor(%q,%d) = %d out of valid host-port range", honeypot, port, hp1)
		}
	})
}
