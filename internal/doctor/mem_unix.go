//go:build !windows

package doctor

import (
	"os"
	"strconv"
	"strings"
)

// TotalMemoryBytes returns physical memory from /proc/meminfo (Linux), or 0.
func TotalMemoryBytes() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}
