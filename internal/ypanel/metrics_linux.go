//go:build linux

package ypanel

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// collectResources fills the resource gauges from /proc + statfs. Each probe is
// best-effort: a failure leaves that gauge at zero with an honest caption rather
// than aborting the whole snapshot.
func collectResources(h *host) {
	collectCPU(h)
	collectMem(h)
	collectDisk(h)
	collectProcs(h)
}

// collectCPU derives a CPU pressure percentage from the 1-minute load average
// divided by the core count. This avoids the two-sample delay a /proc/stat diff
// would need while still giving the panel a meaningful gauge.
func collectCPU(h *host) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		h.CPUCaption = "load unavailable"
		return
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return
	}
	cores := runtime.NumCPU()
	if cores < 1 {
		cores = 1
	}
	h.CPUPct = clampPct(int((load1 / float64(cores)) * 100))
	h.CPUCaption = fmt.Sprintf("%.2f / %d cores", load1, cores)
}

// collectMem reads /proc/meminfo and reports used = total - available.
func collectMem(h *host) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		h.MemCaption = "meminfo unavailable"
		return
	}
	defer f.Close()

	var totalKB, availKB int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			availKB = parseMeminfoKB(line)
		}
		if totalKB > 0 && availKB > 0 {
			break
		}
	}
	if totalKB <= 0 {
		return
	}
	usedKB := totalKB - availKB
	if usedKB < 0 {
		usedKB = 0
	}
	h.MemPct = clampPct(int((usedKB * 100) / totalKB))
	h.MemCaption = fmt.Sprintf("%.1f / %.1f GB", float64(usedKB)/1048576.0, float64(totalKB)/1048576.0)
}

// parseMeminfoKB extracts the kB value from a "MemTotal:  16329216 kB" line.
func parseMeminfoKB(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// collectDisk reports usage of the filesystem backing the root mount, which is
// where honeypot data and container layers live.
func collectDisk(h *host) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		h.DiskCaption = "statfs unavailable"
		return
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if total == 0 {
		return
	}
	used := total - free
	h.DiskPct = clampPct(int((used * 100) / total))
	h.DiskCaption = fmt.Sprintf("%.0f / %.0f GB", float64(used)/1e9, float64(total)/1e9)
}

// collectProcs counts running processes against the kernel pid_max ceiling.
func collectProcs(h *host) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				count++
			}
		}
	}
	max := readPidMax()
	if max <= 0 {
		max = 32768
	}
	h.ProcPct = clampPct((count * 100) / max)
	h.ProcCaption = fmt.Sprintf("%d / %d", count, max)
}

func readPidMax() int {
	b, err := os.ReadFile(filepath.Join("/proc", "sys", "kernel", "pid_max"))
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return v
}
