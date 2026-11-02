package instance

import (
	"strings"
	"time"
)

// releaseDates is roughly when each profile's advertised point release came
// out; a box cannot have been installed before its OS existed.
var releaseDates = map[string]time.Time{
	"focal":    time.Date(2023, 3, 23, 0, 0, 0, 0, time.UTC), // 20.04.6
	"bullseye": time.Date(2023, 10, 7, 0, 0, 0, 0, time.UTC), // 11.8
	"jammy":    time.Date(2023, 8, 10, 0, 0, 0, 0, time.UTC), // 22.04.3
	"bookworm": time.Date(2023, 10, 7, 0, 0, 0, 0, time.UTC), // 12.2
	"noble":    time.Date(2024, 4, 25, 0, 0, 0, 0, time.UTC), // 24.04
}

// installTime is this instance's (fake) OS install date: a seed-chosen day in
// the six months after its release, at a working-hours time of day.
func installTime(p distroProfile, seed string) time.Time {
	base, ok := releaseDates[p.Codename]
	if !ok {
		base = time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	}
	day := seededIndex("install-day:"+seed, 180)
	sec := 8*3600 + seededIndex("install-sec:"+seed, 10*3600)
	return base.AddDate(0, 0, day).Add(time.Duration(sec) * time.Second)
}

// stampFileTimes gives every generated file a stable, believable mtime instead
// of the container start time (identical for all files, and changing on every
// restart). System files date from install, a user's dotfiles from when that
// account was created, and activity files (shell history, known_hosts) from a
// later point. /proc files keep 0 = boot time, as on a real system. Times are
// absolute and depend only on the seed, except that activity is capped to the
// past relative to now.
func stampFileTimes(files []embeddedFile, p distroProfile, seed string, now time.Time) {
	install := installTime(p, seed)
	for i := range files {
		path := files[i].Path
		if strings.HasPrefix(path, "/proc/") {
			continue
		}
		jitter := time.Duration(seededIndex("mtime-jitter:"+seed+path, 900)) * time.Second
		t := install.Add(jitter)
		if home := homeDirOf(path); home != "" {
			// Account created some days after install.
			created := install.AddDate(0, 0, 1+seededIndex("user-created:"+seed+home, 60))
			t = created.Add(jitter)
			if strings.HasSuffix(path, "/.bash_history") || strings.HasSuffix(path, "/.ssh/known_hosts") {
				t = created.AddDate(0, 0, 20+seededIndex("activity:"+seed+path, 400)).Add(jitter)
			}
		}
		if limit := now.Add(-26 * time.Hour); t.After(limit) {
			t = limit.Add(-jitter)
		}
		files[i].MTime = t.Unix()
	}
}

// homeDirOf returns "/root" or "/home/<user>" for a path inside a home
// directory, else "".
func homeDirOf(path string) string {
	if path == "/root" || strings.HasPrefix(path, "/root/") {
		return "/root"
	}
	if rest, ok := strings.CutPrefix(path, "/home/"); ok {
		if user, _, _ := strings.Cut(rest, "/"); user != "" {
			return "/home/" + user
		}
	}
	return ""
}
