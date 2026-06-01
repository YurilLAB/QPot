package instance

// deploy.go describes the per-honeypot container runtime requirements.
//
// Each upstream honeypot image expects specific mount points, tmpfs, and ports
// — a single generic "/var/log/honeypot + /data" mount (the previous behavior)
// does not work for any of them, so honeypots either failed to start or wrote
// their logs to a path the collector never reads. These profiles are derived
// from T-Pot's reference compose files (vendored under docker/<name>/) and the
// cowrie/endlessh profiles are verified by actually running the images.

// deployVolume maps a host subdirectory (under {DataPath}/honeypots/<name>) to
// a path inside the honeypot container.
type deployVolume struct {
	HostSubdir    string
	ContainerPath string
}

// honeypotDeploy is the deployment profile for one honeypot image.
type honeypotDeploy struct {
	// Tmpfs are raw docker-compose tmpfs entries the image needs (e.g. cowrie
	// requires a writable /tmp/cowrie for its pidfile and state).
	Tmpfs []string
	// Volumes are host-subdir -> container-path mounts. The "logs" subdir, when
	// present, is the directory the collector (Vector) reads
	// ({DataPath}/honeypots/<name>/logs), so each honeypot's log path must mount
	// from that subdir.
	Volumes []deployVolume
	// Ports are the container ports to publish. Each is given a deterministic
	// host port via Config.AllocatePort. Empty means "use the honeypot's
	// configured HP.Port" (generic fallback).
	Ports []int
	// ConfigSubdir is the host subdir into which generated config files
	// (cowrie.cfg, userdb.txt, ...) are written. It must be one of the Volumes'
	// HostSubdir so the files land inside a mounted directory.
	ConfigSubdir string
}

// NeedsNetBind reports whether the honeypot binds a privileged port (<1024)
// INSIDE the container. Such images (e.g. cowrie on 22/23) need
// CAP_NET_BIND_SERVICE in the capability bounding set; without it, exec of a
// binary carrying file capabilities fails with EPERM under cap_drop=ALL. This
// is keyed on the container-internal ports, not the host-facing HP.Port.
func (d honeypotDeploy) NeedsNetBind() bool {
	for _, p := range d.Ports {
		if p > 0 && p < 1024 {
			return true
		}
	}
	return false
}

// deployProfileFor returns the deployment profile for a honeypot by name.
// Unknown honeypots get a generic profile (legacy behavior) so they are not
// broken further, but the verified images (cowrie, endlessh) get correct specs.
func deployProfileFor(name string) honeypotDeploy {
	switch name {
	case "cowrie":
		// Verified by running ghcr.io/telekom-security/cowrie:24.04.1: needs a
		// writable etc (cowrie auto-generates SSH host keys there and reads
		// cowrie.cfg/userdb.txt from it), tmpfs /tmp/cowrie for its pidfile, and
		// listens on 22 (SSH) + 23 (telnet).
		return honeypotDeploy{
			Tmpfs: []string{
				"/tmp/cowrie:uid=2000,gid=2000",
				"/tmp/cowrie/data:uid=2000,gid=2000",
			},
			Volumes: []deployVolume{
				{HostSubdir: "etc", ContainerPath: "/home/cowrie/cowrie/etc"},
				{HostSubdir: "logs", ContainerPath: "/home/cowrie/cowrie/log"},
				{HostSubdir: "dl", ContainerPath: "/home/cowrie/cowrie/dl"},
			},
			Ports:        []int{22, 23},
			ConfigSubdir: "etc",
		}
	case "endlessh":
		// Verified: endlessh redirects its log to /var/log/endlessh and listens
		// on 2222 inside the container (T-Pot maps host 22 -> 2222).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/endlessh"},
			},
			Ports: []int{2222},
		}
	default:
		// Generic fallback for honeypots without a verified profile.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/honeypot"},
				{HostSubdir: "data", ContainerPath: "/data"},
			},
		}
	}
}
