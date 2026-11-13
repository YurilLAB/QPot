//go:build !linux

package diskguard

// KeepLogRoom keeps no room on this system: see the Linux version.
func KeepLogRoom(dir string) (LogRoomResult, error) {
	return LogRoomResult{}, ErrLogRoomUnsupported
}
