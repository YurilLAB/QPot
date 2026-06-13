package ypanel

import (
	"os"
	"runtime"
	"time"
)

// host holds the real, self-reported system facts the snapshot needs. The
// platform-specific resource gauges are filled by collectResources (see
// metrics_linux.go for the real /proc + statfs implementation and
// metrics_other.go for the honest non-Linux fallback).
type host struct {
	Hostname string
	OSLabel  string
	Arch     string
	BootedAt string // RFC3339, when this QPot process started

	CPUPct      int
	CPUCaption  string
	MemPct      int
	MemCaption  string
	DiskPct     int
	DiskCaption string
	ProcPct     int
	ProcCaption string
}

// processStart is captured once when the package loads so bootedAt reflects how
// long this QPot instance has actually been up, not the host's boot time.
var processStart = time.Now()

// collectHost gathers host identity plus the resource gauges. Identity is
// portable; the gauges are real on Linux (where honeypot hosts run) and an
// honest placeholder elsewhere.
func collectHost() host {
	name, err := os.Hostname()
	if err != nil || name == "" {
		name = "qpot-host"
	}
	h := host{
		Hostname: name,
		OSLabel:  runtime.GOOS,
		Arch:     runtime.GOARCH,
		BootedAt: processStart.UTC().Format(time.RFC3339),
	}
	collectResources(&h)
	return h
}

// clampPct keeps a percentage inside the [0,100] window the worker validates.
func clampPct(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
