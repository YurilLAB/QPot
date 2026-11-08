package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/cleanup"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

func newCleanupCommand() *cobra.Command {
	var instanceName string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Remove old captured files, logs and backup days to keep the instance within its disk limits",
		Long: `Keep what the instance stores outside its database within its limits, as
qpot serve does every hour (see the cleanup section of the config):

  - captured files (downloads, session recordings, uploads, payloads), rotated
    logs and collector backup days older than cleanup.max_age_days go;
  - a log the collector reads that is larger than cleanup.max_log_mb is
    emptied, only while the collector runs (its events are already stored);
  - a honeypot folder above its storage limit (max_storage_gb) loses its
    oldest captured files first; its state and settings are never touched;
  - the collector's backup folder loses its oldest days above
    cleanup.max_backup_mb, never the current day.

--dry-run only says what it would do. It runs even when automatic cleanup
is off.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
			defer cancel()
			running := false
			if mgr, err := instance.NewManager(cfg); err == nil {
				sctx, scancel := context.WithTimeout(ctx, 30*time.Second)
				if states, err := mgr.ServiceStates(sctx); err == nil {
					running = states["collector"].State == "running"
				}
				scancel()
			}
			var helper cleanup.Helper
			if runtime.GOOS != "windows" {
				helper = &cleanup.DockerHelper{Image: instance.CollectorImage}
			}
			rep := cleanup.Run(ctx, cfg, cleanup.LimitsFor(cfg), cleanup.Options{DryRun: dryRun, CollectorRunning: running, Helper: helper})
			printCleanup(rep)
			if len(rep.Errors) > 0 {
				return fmt.Errorf("cleanup could not do everything (%d errors above)", len(rep.Errors))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "only say what would be removed or emptied")
	return cmd
}

func printCleanup(rep *cleanup.Report) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FOLDER\tON DISK\tLIMIT\tFREED\tREMOVED\tEMPTIED")
	for _, a := range rep.Areas {
		limit := "none"
		if a.Limit > 0 {
			limit = humanSize(a.Limit)
		}
		over := ""
		if a.Over {
			over = "  (over its limit)"
		}
		fmt.Fprintf(w, "%s\t%s%s\t%s\t%s\t%d\t%d\n", a.Name, humanSize(a.Bytes), over, limit, humanSize(a.Freed), a.Removed, a.Emptied)
	}
	_ = w.Flush()
	verb, removed, emptied := "Freed", "removed", "emptied"
	if rep.DryRun {
		verb, removed, emptied = "Would free", "to remove", "to empty"
	}
	fmt.Printf("\n[OK] %s %s: %d files %s, %d logs %s.\n", verb, humanSize(rep.Freed), rep.Removed, removed, rep.Emptied, emptied)
	if !rep.Collector {
		fmt.Println("     The collector is not running: no log was emptied.")
	}
	for _, n := range rep.Notes {
		fmt.Println("     " + n)
	}
	for _, e := range rep.Errors {
		fmt.Println("[!!] " + e)
	}
}

// humanSize is n bytes in the largest unit that keeps it at least 1.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n), 0
	for v >= unit && i < 4 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %ciB", v, "KMGT"[i-1])
}
