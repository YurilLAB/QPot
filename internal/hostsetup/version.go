package hostsetup

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a major.minor.patch version as Docker and Compose print it.
type Version struct {
	Major, Minor, Patch int
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Less reports whether v is older than w.
func (v Version) Less(w Version) bool {
	if v.Major != w.Major {
		return v.Major < w.Major
	}
	if v.Minor != w.Minor {
		return v.Minor < w.Minor
	}
	return v.Patch < w.Patch
}

// Minimum versions QPot needs. Engine 20.10 brought cgroup v2 and the
// Compose v2 integration; Compose 2 is the `docker compose` command QPot runs.
var (
	MinEngine  = Version{20, 10, 0}
	MinCompose = Version{2, 0, 0}
)

// ParseVersion reads the version from what `docker version --format`,
// `docker --version` or `docker compose version --short` print, for example
// "27.3.1", "20.10.24+dfsg1", "v2.29.7", "2.29.7-desktop.1" or
// "Docker version 27.3.1, build ce12230". Missing minor or patch parts read
// as 0. The first token that starts with a digit (after an optional "v") is
// used.
func ParseVersion(s string) (Version, error) {
	if len(s) > 4096 {
		s = s[:4096]
	}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' || r == '\r' }) {
		tok = strings.TrimPrefix(strings.TrimPrefix(tok, "v"), "V")
		if tok == "" || tok[0] < '0' || tok[0] > '9' {
			continue
		}
		// Cut build metadata and pre-release suffixes: "+dfsg1", "-rc.1", "~ubuntu".
		if i := strings.IndexAny(tok, "+-~_"); i >= 0 {
			tok = tok[:i]
		}
		parts := strings.SplitN(tok, ".", 4)
		var nums [3]int
		ok := true
		for i := 0; i < 3 && i < len(parts); i++ {
			if parts[i] == "" || len(parts[i]) > 6 {
				ok = false
				break
			}
			n, err := strconv.Atoi(parts[i])
			if err != nil || n < 0 {
				ok = false
				break
			}
			nums[i] = n
		}
		if ok {
			return Version{nums[0], nums[1], nums[2]}, nil
		}
	}
	return Version{}, fmt.Errorf("no version number in %q", truncate(s, 60))
}
