package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/hostsetup"
)

// setupSources are the files whose errors reach the user through
// `qpot setup` and `qpot doctor`.
func setupSources(t *testing.T) []string {
	t.Helper()
	files := []string{"setup.go", "setup_flow.go", "setup_answers.go", "setup_prompt.go", "setup_summary.go", "setup_tty.go"}
	more, err := filepath.Glob(filepath.Join("..", "..", "internal", "hostsetup", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range more {
		if !strings.HasSuffix(f, "_test.go") {
			files = append(files, f)
		}
	}
	return files
}

// uncodedAllowed lists the only places that may build a plain error, each
// because its caller always turns the result into a coded error.
var uncodedAllowed = map[string]string{
	"pgp.go:":                          "errKey sentinel; KeyFingerprint's callers code it as QP-NET-005",
	"version.go:ParseVersion":          "callers ignore the error and keep the zero version",
	"runner.go:Run":                    "Result.Err of an empty command; ClassifyFailure codes every failed Result",
	"proc_windows.go:interruptProcess": "never shown: Run kills the process instead",
	"setup_answers.go:saveSetupState":  "runSetupSteps wraps it as QP-PERM-007",
}

// No error in setup is made with fmt.Errorf or errors.New (except the
// reviewed places above): every one must come from the catalog through
// hostsetup.E, so it reaches the user with a code, a cause and a fix.
// Every code named in the source must exist in the catalog.
func TestSetupErrorsAreCoded(t *testing.T) {
	known := map[string]bool{}
	for _, c := range hostsetup.Codes() {
		known[c.ID] = true
	}
	used := map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range setupSources(t) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Base(path)
		check := func(fn string) func(ast.Node) bool {
			return func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok {
							plain := (id.Name == "fmt" && sel.Sel.Name == "Errorf") || (id.Name == "errors" && sel.Sel.Name == "New")
							if plain {
								if _, ok := uncodedAllowed[base+":"+fn]; !ok {
									t.Errorf("%s: %s.%s in %s builds an error without a code; use hostsetup.E", fset.Position(x.Pos()), id.Name, sel.Sel.Name, fn)
								}
							}
						}
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if s, err := strconv.Unquote(x.Value); err == nil && strings.HasPrefix(s, "QP-") && len(s) <= 14 && !strings.ContainsAny(s, " <%") {
							if base != "errors.go" {
								used[s] = true
							}
							if !known[s] {
								t.Errorf("%s: %q is not in the error catalog", fset.Position(x.Pos()), s)
							}
						}
					}
				}
				return true
			}
		}
		for _, d := range f.Decls {
			name := ""
			if fd, ok := d.(*ast.FuncDecl); ok {
				name = fd.Name.Name
			}
			ast.Inspect(d, check(name))
		}
	}
	// Catalog codes nothing uses are fine (the install scripts and doctor
	// use some), but report the count so an unused code is noticed.
	var unused []string
	for c := range known {
		if !used[c] {
			unused = append(unused, c)
		}
	}
	sort.Strings(unused)
	t.Logf("%d codes in the catalog, %d named in the Go sources; not named there: %v", len(known), len(used), unused)
}
