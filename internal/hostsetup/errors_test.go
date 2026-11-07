package hostsetup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// docPath is the generated reference of every code.
var docPath = filepath.Join("..", "..", "doc", "setup-errors.md")

func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	exits := map[int]string{}
	for _, cat := range categories {
		if prev, dup := exits[cat.Exit]; dup {
			t.Errorf("categories %s and %s share exit status %d", prev, cat.Key, cat.Exit)
		}
		exits[cat.Exit] = cat.Key
		if cat.Exit <= 1 || cat.Exit > 255 {
			t.Errorf("category %s: exit status %d must be 2..255 (0 is success, 1 is a usage error)", cat.Key, cat.Exit)
		}
	}
	for _, c := range catalog {
		if !codeRe.MatchString(c.ID) {
			t.Errorf("%q is not QP-<CATEGORY>-<NNN>", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("code %s is used twice", c.ID)
		}
		seen[c.ID] = true
		if _, ok := CategoryOf(c.Category()); !ok {
			t.Errorf("%s: unknown category %q", c.ID, c.Category())
		}
		for field, v := range map[string]string{"title": c.Title, "cause": c.Cause, "fix": c.Fix} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: empty %s", c.ID, field)
			}
			if strings.ContainsAny(v, "\n\t\r") {
				t.Errorf("%s: %s has a control character", c.ID, field)
			}
		}
		if !strings.HasSuffix(c.Title, ".") {
			t.Errorf("%s: title should be a sentence ending in '.': %q", c.ID, c.Title)
		}
	}
	for _, cat := range categories {
		n := 0
		for _, c := range catalog {
			if c.Category() == cat.Key {
				n++
			}
		}
		if n == 0 {
			t.Errorf("category %s has no codes", cat.Key)
		}
	}
}

// The reference document is generated from the catalog: any difference (a
// code removed from the doc, a stale code left in it, a changed fix) fails.
func TestErrorDocInSync(t *testing.T) {
	want := RenderDoc()
	if os.Getenv("QPOT_UPDATE_DOCS") == "1" {
		if err := os.WriteFile(docPath, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with QPOT_UPDATE_DOCS=1)", docPath, err)
	}
	gotS := strings.ReplaceAll(string(got), "\r\n", "\n")
	docCodes := map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^### (QP-[A-Z]+-[0-9]{3})$`).FindAllStringSubmatch(gotS, -1) {
		docCodes[m[1]]++
	}
	for _, c := range catalog {
		if docCodes[c.ID] != 1 {
			t.Errorf("%s appears %d times as a heading in %s", c.ID, docCodes[c.ID], docPath)
		}
		delete(docCodes, c.ID)
	}
	for stale := range docCodes {
		t.Errorf("%s documents %s, which is not in the catalog", docPath, stale)
	}
	if gotS != want {
		t.Errorf("%s is out of date; regenerate with: QPOT_UPDATE_DOCS=1 go test ./internal/hostsetup -run TestErrorDocInSync", docPath)
	}
}

func TestExitStatusFollowsCategory(t *testing.T) {
	for _, c := range catalog {
		cat, _ := CategoryOf(c.Category())
		if got := ExitStatus(c.ID); got != cat.Exit {
			t.Errorf("ExitStatus(%s) = %d, want %d", c.ID, got, cat.Exit)
		}
	}
	if ExitStatus("QP-NOPE-001") != 70 {
		t.Error("an unknown code must exit with the BUG status")
	}
	// The exit statuses are published (README, cli-reference, scripts check
	// them): they never change once released.
	published := map[string]int{"INPUT": 10, "HOST": 11, "PERM": 12, "NET": 13, "PKG": 14, "DOCKER": 15,
		"COMPOSE": 16, "PORT": 17, "RES": 18, "SVC": 19, "WEB": 20, "INST": 21, "INTEL": 22, "CLUSTER": 23, "INT": 130, "BUG": 70}
	cats := Categories()
	if len(cats) != len(published) {
		t.Errorf("%d categories, %d published", len(cats), len(published))
	}
	for _, c := range cats {
		if want, ok := published[c.Key]; !ok || c.Exit != want {
			t.Errorf("category %s exits %d; the published status is %d", c.Key, c.Exit, want)
		}
	}
}

func TestLookupForgivesTyping(t *testing.T) {
	for _, in := range []string{"QP-PKG-001", "qp-pkg-001", " QP-PKG-1 ", "pkg-001", "PKG 1", "qp_pkg_001", "QPPKG001"} {
		c, ok := Lookup(in)
		if !ok || c.ID != "QP-PKG-001" {
			t.Errorf("Lookup(%q) = %v, %v", in, c.ID, ok)
		}
	}
	for _, in := range []string{"", "QP-PKG-1000", "QP-PKG-999", "PKG", "QP--001", strings.Repeat("A", 100)} {
		if c, ok := Lookup(in); ok {
			t.Errorf("Lookup(%q) found %s", in, c.ID)
		}
	}
	if _, err := Explain("QP-NOPE-1"); err == nil || AsError(err).Code != "QP-INPUT-011" {
		t.Errorf("Explain(unknown) = %v", err)
	}
	text, err := Explain("qp-port-001")
	if err != nil || !strings.Contains(text, "QP-PORT-001") || !strings.Contains(text, "exit status 17") {
		t.Errorf("Explain = %q, %v", text, err)
	}
}

func TestAsErrorCodesEverything(t *testing.T) {
	if AsError(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	cases := []struct {
		err  error
		code string
	}{
		{context.Canceled, "QP-INT-001"},
		{fmt.Errorf("step: %w", context.Canceled), "QP-INT-001"},
		{context.DeadlineExceeded, "QP-INT-002"},
		{errors.New("plain"), "QP-BUG-001"},
		{E("QP-PKG-001"), "QP-PKG-001"},
		{fmt.Errorf("wrapped: %w", E("QP-NET-002")), "QP-NET-002"},
	}
	for _, c := range cases {
		if got := AsError(c.err); got.Code != c.code {
			t.Errorf("AsError(%v) = %s, want %s", c.err, got.Code, c.code)
		}
	}
	e := AsError(errors.New("raw text"))
	if e.Details != "raw text" {
		t.Errorf("details lost: %q", e.Details)
	}
}

func TestEPanicsOnUnknownCode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("E accepted a code that is not in the catalog")
		}
	}()
	E("QP-PKG-999")
}

func TestSpecificWhyAndFixOverrideCatalog(t *testing.T) {
	e := E("QP-PORT-001")
	if e.Cause() != e.Entry().Cause || e.Remedy() != e.Entry().Fix {
		t.Fatal("defaults must come from the catalog")
	}
	e.WithWhy("port %d", 9).WithFix("use %d", 10)
	if e.Cause() != "port 9" || e.Remedy() != "use 10" {
		t.Fatalf("override: %q / %q", e.Cause(), e.Remedy())
	}
	if e.Error() != "QP-PORT-001: "+e.Entry().Title {
		t.Fatalf("Error() = %q", e.Error())
	}
}

// The install scripts print the same codes and exit with the same
// statuses; a code they use must exist, and their category-to-status table
// must match the catalog's.
func TestInstallScriptsUseCatalogCodes(t *testing.T) {
	codeInText := regexp.MustCompile(`QP-[A-Z]+-[0-9]{3}`)
	for _, name := range []string{"install.sh", "install.ps1"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		found := codeInText.FindAllString(text, -1)
		if len(found) < 4 {
			t.Errorf("%s uses only %d error codes", name, len(found))
		}
		for _, c := range found {
			if _, ok := byID[c]; !ok {
				t.Errorf("%s uses %s, which is not in the catalog", name, c)
			}
		}
		// The scripts map a category to its exit status in one table:
		//   install.sh:  HOST) echo 11 ;;     install.ps1:  'HOST' = 11
		re := regexp.MustCompile(`(?m)^\s*'?([A-Z]+)'?\)?\s*(?:=|\)\s*echo)\s*([0-9]+)`)
		got := map[string]int{}
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if _, ok := CategoryOf(m[1]); ok {
				n, _ := strconv.Atoi(m[2])
				got[m[1]] = n
			}
		}
		if len(got) == 0 {
			t.Errorf("%s has no category-to-exit-status table", name)
		}
		var keys []string
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			cat, _ := CategoryOf(k)
			if got[k] != cat.Exit {
				t.Errorf("%s exits %d for %s; the catalog says %d", name, got[k], k, cat.Exit)
			}
		}
		for _, c := range found {
			if _, ok := got[byID[c].Category()]; !ok {
				t.Errorf("%s uses %s but has no exit status for category %s", name, c, byID[c].Category())
			}
		}
	}
}

func FuzzLookupCode(f *testing.F) {
	for _, c := range catalog {
		f.Add(c.ID)
		f.Add(strings.ToLower(c.ID))
	}
	f.Add("")
	f.Add("QP-\x1b]52;c;AAAA\x07-001")
	f.Add("pkg 01")
	f.Fuzz(func(t *testing.T, s string) {
		c, ok := Lookup(s)
		text, err := Explain(s)
		if ok != (err == nil) {
			t.Fatalf("Lookup and Explain disagree on %q", s)
		}
		if !ok {
			if AsError(err).Code != "QP-INPUT-011" {
				t.Fatalf("Explain(%q) = %v", s, err)
			}
			return
		}
		if _, known := byID[c.ID]; !known {
			t.Fatalf("Lookup(%q) returned unknown %q", s, c.ID)
		}
		if again, ok := Lookup(c.ID); !ok || again.ID != c.ID {
			t.Fatalf("round trip of %s failed", c.ID)
		}
		// Explain prints only catalog text: nothing from the input.
		if strings.ContainsAny(text, "\x1b\x07") || !strings.HasPrefix(text, c.ID+": ") {
			t.Fatalf("Explain(%q) = %q", s, text)
		}
	})
}
