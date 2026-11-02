//go:build !linux

package overview

// collectResources is the non-Linux fallback. Honeypot hosts run Linux, where
// real /proc + statfs readings are available (metrics_linux.go); elsewhere the
// gauges say so rather than showing invented numbers.
func collectResources(h *host) {
	const caption = "measured on Linux hosts only"
	h.CPUCaption = caption
	h.MemCaption = caption
	h.DiskCaption = caption
	h.ProcCaption = caption
}
