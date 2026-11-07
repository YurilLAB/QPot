package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestPlatformsMatchMakefile: `make build-all` and the release build the
// same platforms, so the installers find an archive for each one the
// Makefile builds.
func TestPlatformsMatchMakefile(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^PLATFORMS = (.+)$`).FindSubmatch(data)
	if m == nil {
		t.Fatal("no PLATFORMS line in the Makefile")
	}
	if got := strings.Join(strings.Fields(string(m[1])), " "); got != defaultPlatforms {
		t.Fatalf("Makefile PLATFORMS %q, qpot-release builds %q", got, defaultPlatforms)
	}
}
