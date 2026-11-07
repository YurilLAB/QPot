package release

import (
	"fmt"
	"regexp"
	"strings"
)

// Version is a release version, MAJOR.MINOR.PATCH with an optional
// pre-release part ("0.2.0-rc.1").
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Tag is the git tag that publishes v: "v" + the version.
func (v Version) Tag() string { return "v" + v.String() }

// SemVer 2.0 core with an optional pre-release; no build metadata (a "+"
// would not survive as a release file name on every system).
var versionRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-((?:0|[1-9][0-9]{0,8}|[0-9]*[A-Za-z-][0-9A-Za-z-]{0,31})(?:\.(?:0|[1-9][0-9]{0,8}|[0-9]*[A-Za-z-][0-9A-Za-z-]{0,31})){0,7}))?$`)

// MaxVersionLen keeps every release file name a valid SHA256SUMS name (at
// most MaxNameLen characters): the longest is the provenance file,
// "qpot_" + version + "_provenance.sigstore.json".
const MaxVersionLen = MaxNameLen - len("qpot_") - len("_provenance.sigstore.json")

// ParseVersion parses "0.1.0" or "0.2.0-rc.1".
func ParseVersion(s string) (Version, error) {
	if len(s) > MaxVersionLen {
		return Version{}, fmt.Errorf("release: the version %q is longer than %d characters", truncate(s, 40), MaxVersionLen)
	}
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("release: %q is not a version like 1.2.3 or 1.2.3-rc.1", truncate(s, 40))
	}
	var v Version
	// The pattern allows at most nine digits, so these cannot overflow.
	_, _ = fmt.Sscan(m[1], &v.Major)
	_, _ = fmt.Sscan(m[2], &v.Minor)
	_, _ = fmt.Sscan(m[3], &v.Patch)
	v.Pre = m[4]
	return v, nil
}

// ParseTag parses a release tag: "v" followed by a version.
func ParseTag(tag string) (Version, error) {
	rest, ok := strings.CutPrefix(tag, "v")
	if !ok {
		return Version{}, fmt.Errorf("release: tag %q does not start with v", truncate(tag, 40))
	}
	return ParseVersion(rest)
}

// ArchiveName is the release archive for a platform, as the installers
// name it: qpot_<version>_<os>_<arch>.tar.gz, or .zip for Windows.
func ArchiveName(v Version, goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return "qpot_" + v.String() + "_" + goos + "_" + goarch + ext
}

// ProvenanceName is the release file that holds the build provenance
// attestation (a Sigstore bundle) for every archive of v.
func ProvenanceName(v Version) string { return "qpot_" + v.String() + "_provenance.sigstore.json" }

// SumsName is the checksum list of a release.
const SumsName = "SHA256SUMS"

// Where each file that names the release version keeps it. The installers
// download exactly this version, so a tag that does not match them would
// publish a release nobody installs.
var versionSources = []struct {
	file string
	re   *regexp.Regexp
}{
	{"scripts/install.sh", regexp.MustCompile(`(?m)^QPOT_VERSION="([^"\n]*)"`)},
	{"scripts/install.ps1", regexp.MustCompile(`(?m)^\$QPOT_VERSION = "([^"\n]*)"`)},
	{"Makefile", regexp.MustCompile(`(?m)^VERSION \?= (\S+)\s*$`)},
}

// VersionFiles lists the files CheckVersions reads.
func VersionFiles() []string {
	out := make([]string, len(versionSources))
	for i, s := range versionSources {
		out[i] = s.file
	}
	return out
}

// CheckVersions checks that every file in VersionFiles names exactly
// version want. read returns a file's contents by its repository path.
func CheckVersions(want Version, read func(string) ([]byte, error)) error {
	var bad []string
	for _, s := range versionSources {
		data, err := read(s.file)
		if err != nil {
			return err
		}
		m := s.re.FindAllSubmatch(data, -1)
		switch {
		case len(m) != 1:
			bad = append(bad, fmt.Sprintf("%s: expected one version line, found %d", s.file, len(m)))
		case string(m[0][1]) != want.String():
			bad = append(bad, fmt.Sprintf("%s: version %q, the tag says %q", s.file, truncate(string(m[0][1]), 40), want.String()))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("release: the version does not match:\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
