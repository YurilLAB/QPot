//go:build !linux

package ypanel

import "time"

// collectResources is the non-Linux fallback. QPot's honeypot hosts run Linux,
// where the real /proc + statfs gauges are available (see metrics_linux.go). On
// other platforms (a developer's macOS/Windows box) we report an honest
// placeholder: the host shows online with an uptime caption rather than
// fabricated utilisation numbers the panel would present as real.
func collectResources(h *host) {
	uptime := time.Since(processStart).Round(time.Second)
	caption := "metrics in the Linux build · up " + uptime.String()
	h.CPUCaption = caption
	h.MemCaption = caption
	h.DiskCaption = caption
	h.ProcCaption = caption
}
