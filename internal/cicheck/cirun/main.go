// Command cirun runs jobs of .github/workflows/ci.yml on this machine the
// way GitHub Actions runs them. scripts/ci-local.sh drives it:
//
//	cirun list        one line per job: id, runs-on, and "docker" when it
//	                  needs Docker (service containers)
//	cirun check       fails when a job uses something cirun cannot run
//	cirun run <job>   runs one job (every matrix entry)
//	cirun check-codeql <dir> validates CodeQL SARIF before publication
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/qpot/qpot/internal/cicheck"
)

func main() {
	root := flag.String("root", ".", "the repository root")
	workflow := flag.String("workflow", ".github/workflows/ci.yml", "the workflow, relative to -root")
	tools := flag.String("tools", ".github/ci-tools.env", "the shared tool versions, relative to -root")
	gitleaksRange := flag.String("gitleaks-range", "", "override a legacy gitleaks-action log range; current CI always scans full history")
	flag.Parse()
	abs, err := filepath.Abs(*root)
	if err != nil {
		fail(err)
	}
	if cmd := flag.Arg(0); cmd == "secrets-source" || cmd == "secrets-artifacts" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := cicheck.RunSecretGateCommand(ctx, abs, cmd, flag.Args()[1:], os.Stdout); err != nil {
			fail(err)
		}
		return
	}
	if flag.Arg(0) == "check-codeql" {
		if flag.NArg() != 2 && flag.NArg() != 3 {
			fail(fmt.Errorf("usage: cirun check-codeql <SARIF output directory> [review manifest]"))
		}
		var summary cicheck.CodeQLSummary
		if flag.NArg() == 3 {
			summary, err = cicheck.CheckReviewedCodeQLReports(abs, flag.Arg(1), flag.Arg(2))
		} else {
			summary, err = cicheck.CheckCodeQLReports(flag.Arg(1))
		}
		if err != nil {
			fail(err)
		}
		fmt.Printf("CodeQL release gate passed: %d reports, %d rules, %d reviewed findings, %d non-security results\n", summary.Reports, summary.Rules, summary.Reviewed, summary.Results-summary.Reviewed)
		return
	}
	if flag.Arg(0) == "check-image-index" {
		if flag.NArg() != 2 {
			fail(fmt.Errorf("usage: cirun check-image-index <published image index JSON>"))
		}
		if err := cicheck.CheckImageIndex(flag.Arg(1)); err != nil {
			fail(err)
		}
		fmt.Println("Published image index includes both tested Linux architectures")
		return
	}
	data, err := os.ReadFile(filepath.Join(abs, *workflow)) // #nosec G304 -- the repository's own workflow
	if err != nil {
		fail(err)
	}
	w, err := cicheck.ParseWorkflow(data)
	if err != nil {
		fail(err)
	}
	tdata, err := os.ReadFile(filepath.Join(abs, *tools)) // #nosec G304 -- the repository's own file
	if err != nil {
		fail(err)
	}
	tv, err := cicheck.ParseToolsEnv(tdata)
	if err != nil {
		fail(err)
	}
	r := &cicheck.Runner{Root: abs, Tools: tv, Out: os.Stdout, Env: os.Environ(), GitleaksRange: *gitleaksRange}
	switch flag.Arg(0) {
	case "list":
		for _, j := range w.Jobs {
			need := "-"
			if len(j.Services) > 0 {
				need = "docker"
			}
			fmt.Printf("%s\t%s\t%s\n", j.ID, j.RunsOn, need)
		}
	case "check":
		bad := false
		for _, j := range w.Jobs {
			if err := r.Check(w, j); err != nil {
				fmt.Fprintln(os.Stderr, err)
				bad = true
			}
		}
		if bad {
			os.Exit(1)
		}
	case "run":
		j, ok := w.Job(flag.Arg(1))
		if !ok {
			fail(fmt.Errorf("no job %q in %s (jobs: %s)", flag.Arg(1), *workflow, jobIDs(w)))
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := r.RunJob(ctx, w, j); err != nil {
			fmt.Fprintln(os.Stderr, "cirun:", err)
			stop()
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: cirun [flags] list | check | run <job> | check-codeql <dir> | secrets-source [flags] | secrets-artifacts [flags]")
		os.Exit(2)
	}
}

func jobIDs(w *cicheck.Workflow) string {
	var ids []string
	for _, j := range w.Jobs {
		ids = append(ids, j.ID)
	}
	return strings.Join(ids, ", ")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cirun:", err)
	os.Exit(2)
}
