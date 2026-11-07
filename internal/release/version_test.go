package release

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	good := map[string]Version{
		"0.1.0":                 {0, 1, 0, ""},
		"1.2.3-rc.1":            {1, 2, 3, "rc.1"},
		"10.20.30-alpha.beta.1": {10, 20, 30, "alpha.beta.1"},
		"0.0.0-0a":              {0, 0, 0, "0a"},
	}
	for s, want := range good {
		got, err := ParseVersion(s)
		if err != nil || got != want || got.String() != s {
			t.Errorf("ParseVersion(%q) = %+v, %v; want %+v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "v0.1.0", "01.2.3", "1.02.3", "1.2", "1.2.3.4", "1.2.3+build", "1.2.3-",
		"1.2.3-01", "1.2.3-rc..1", " 1.2.3", "1.2.3\n", "1.2.3-rc_1", "1234567890.0.0", "1.2.3-a/b"} {
		if v, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q) accepted: %+v", s, v)
		}
	}
	// The longest version still gives file names the sums list accepts;
	// one character more is refused (found by FuzzParseVersion).
	id := strings.Repeat("a", 30)
	longest := "0.0.0-" + id + "." + id + "." + id
	if len(longest) != MaxVersionLen {
		t.Fatalf("the longest test version has %d characters, want %d", len(longest), MaxVersionLen)
	}
	v, err := ParseVersion(longest)
	if err != nil || !ValidName(ProvenanceName(v)) || !ValidName(ArchiveName(v, "darwin", "arm64")) {
		t.Errorf("ParseVersion(%d characters) = %+v, %v", len(longest), v, err)
	}
	if v, err := ParseVersion(longest + "a"); err == nil {
		t.Errorf("ParseVersion(%d characters) accepted: %+v", len(longest)+1, v)
	}
}

func TestParseTag(t *testing.T) {
	v, err := ParseTag("v0.2.0-rc.1")
	if err != nil || v.Tag() != "v0.2.0-rc.1" {
		t.Fatalf("ParseTag = %+v, %v", v, err)
	}
	for _, s := range []string{"0.1.0", "vv0.1.0", "V0.1.0", "v", "release-0.1.0"} {
		if _, err := ParseTag(s); err == nil {
			t.Errorf("ParseTag(%q) accepted", s)
		}
	}
}

func TestReleaseFileNames(t *testing.T) {
	v := Version{0, 1, 0, ""}
	for _, c := range []struct{ goos, goarch, want string }{
		{"linux", "amd64", "qpot_0.1.0_linux_amd64.tar.gz"},
		{"darwin", "arm64", "qpot_0.1.0_darwin_arm64.tar.gz"},
		{"windows", "amd64", "qpot_0.1.0_windows_amd64.zip"},
	} {
		if got := ArchiveName(v, c.goos, c.goarch); got != c.want || !ValidName(got) {
			t.Errorf("ArchiveName(%s/%s) = %q, want %q", c.goos, c.goarch, got, c.want)
		}
	}
	if p := ProvenanceName(v); p != "qpot_0.1.0_provenance.sigstore.json" || !ValidName(p) {
		t.Errorf("ProvenanceName = %q", p)
	}
}

func TestCheckVersions(t *testing.T) {
	files := map[string]string{
		"scripts/install.sh":  "#!/bin/sh\nQPOT_VERSION=\"0.3.0\"\n",
		"scripts/install.ps1": "$QPOT_VERSION = \"0.3.0\"\r\n",
		"Makefile":            "VERSION ?= 0.3.0\nBINARY = qpot\n",
	}
	read := func(m map[string]string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			s, ok := m[p]
			if !ok {
				return nil, errors.New("no " + p)
			}
			return []byte(s), nil
		}
	}
	if err := CheckVersions(Version{0, 3, 0, ""}, read(files)); err != nil {
		t.Fatalf("matching versions refused: %v", err)
	}
	if err := CheckVersions(Version{0, 3, 1, ""}, read(files)); err == nil || !strings.Contains(err.Error(), "Makefile") {
		t.Errorf("a tag none of the files names passed: %v", err)
	}
	for file, bad := range map[string]string{
		"scripts/install.sh":  "QPOT_VERSION=\"0.3.0\"\nQPOT_VERSION=\"0.4.0\"\n",
		"scripts/install.ps1": "# no version line\n",
		"Makefile":            "VERSION ?= 0.3.0-rc.1\n",
	} {
		m := map[string]string{}
		for k, v := range files {
			m[k] = v
		}
		m[file] = bad
		if err := CheckVersions(Version{0, 3, 0, ""}, read(m)); err == nil || !strings.Contains(err.Error(), file) {
			t.Errorf("%s = %q passed: %v", file, bad, err)
		}
	}
	if err := CheckVersions(Version{0, 3, 0, ""}, read(map[string]string{})); err == nil {
		t.Error("missing files passed")
	}
}

// TestRepositoryVersionsAgree: the installers and the Makefile name one
// version today, so tagging it would pass the release workflow's check.
func TestRepositoryVersionsAgree(t *testing.T) {
	read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(p))) }
	data, err := read("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := versionSources[2].re.FindSubmatch(data)
	if m == nil {
		t.Fatal("no VERSION in the Makefile")
	}
	v, err := ParseVersion(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckVersions(v, read); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"0.1.0", "1.2.3-rc.1", "v1.2.3", "1.2.3-", "01.1.1", "1.2.3-a.b-c.0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err != nil {
			return
		}
		if v.String() != s {
			t.Fatalf("ParseVersion(%q) prints as %q", s, v.String())
		}
		if w, err := ParseTag(v.Tag()); err != nil || w != v {
			t.Fatalf("tag %q parses as %+v, %v", v.Tag(), w, err)
		}
		for _, n := range []string{ArchiveName(v, "linux", "amd64"), ArchiveName(v, "windows", "amd64"), ProvenanceName(v)} {
			if !ValidName(n) {
				t.Fatalf("version %q gives a file name the sums list refuses: %q", s, n)
			}
		}
	})
}
