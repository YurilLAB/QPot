//go:build !linux

package diskguard

// KeepLogRoom keeps no room on this system: see the Linux version.
func KeepLogRoom(dir string, opt LogRoomOptions) (LogRoomResult, error) {
	return LogRoomResult{}, ErrLogRoomUnsupported
}
