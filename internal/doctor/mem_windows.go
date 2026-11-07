//go:build windows

package doctor

// TotalMemoryBytes is not read on Windows (Docker Desktop's VM sets the
// limit); 0 skips the memory check.
func TotalMemoryBytes() int64 { return 0 }
