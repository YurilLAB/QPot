package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// restoreTarget is what `qpot db restore` needs from the database. A test
// puts its own in place of the real connection.
type restoreTarget interface {
	database.EventRestorer
	io.Closer
}

// openRestoreTarget connects to the instance's database and makes sure its
// tables exist: after a lost database volume they do not until the control
// plane has run.
var openRestoreTarget = func(ctx context.Context, cfg *config.Config) (restoreTarget, error) {
	db, err := database.New(cfg.DatabaseClient())
	if err != nil {
		return nil, fmt.Errorf("failed to construct database driver: %w", err)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := db.Connect(connectCtx); err != nil {
		return nil, fmt.Errorf("failed to connect to database (is the instance up?): %w", err)
	}
	if err := db.InitializeSchema(connectCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to prepare the database tables: %w", err)
	}
	target, ok := db.(restoreTarget)
	if !ok {
		_ = db.Close()
		return nil, fmt.Errorf("a %s database cannot be restored from log backups", cfg.Database.Type)
	}
	return target, nil
}

// newDBRestoreCommand puts the events of the collector's log backups back
// into the database.
func newDBRestoreCommand() *cobra.Command {
	var (
		instanceName string
		from         string
		dryRun       bool
		merge        bool
		asJSON       bool
	)
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Rebuild the database's events from the collector's log backups",
		Long: `Reads the collector's log backups (<data>/backup/logs/YYYY/MM/DD/<honeypot>.log)
and stores every event the database does not hold yet, with its own time and ID.

Use it after the database was lost or emptied. Restored events are classified
again by the control plane (qpot serve), which rebuilds indicators and sessions.
The command can be stopped and run again: what is stored is skipped.

Only the days the backups still hold can be restored (see "backup days" in
qpot cleanup).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateInstanceName(instanceName); err != nil {
				return err
			}
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			dir := from
			if dir == "" {
				dir = filepath.Join(cfg.DataPath, "backup", "logs")
			}
			ctx := cmd.Context()
			target, err := openRestoreTarget(ctx, cfg)
			if err != nil {
				return err
			}
			defer target.Close()

			have, err := target.CountEvents(ctx)
			if err != nil {
				return err
			}
			if have > 0 && !merge && !dryRun {
				return fmt.Errorf("the database already holds %d events. Restore is meant for an empty database.\n"+
					"Run with --dry-run to see what is missing, or with --merge to add only the missing events.\n"+
					"With --merge, indicators that were already counted for those events are counted again", have)
			}
			out := cmd.OutOrStdout()
			opt := database.RestoreOptions{DryRun: dryRun}
			if !asJSON {
				opt.Progress = func(file string, rep database.RestoreReport) {
					fmt.Fprintf(out, "  %-32s %d stored, %d already there\n", file, rep.Stored, rep.AlreadyStored)
				}
				fmt.Fprintf(out, "Reading log backups in %s\n", dir)
			}
			rep, err := database.RestoreBackups(ctx, target, dir, opt)
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if jerr := enc.Encode(rep); jerr != nil && err == nil {
					err = jerr
				}
				return err
			}
			verb := "Stored"
			if dryRun {
				verb = "Would store"
			}
			fmt.Fprintf(out, "%s %d events from %d files (%d lines; %d already in the database; %d unreadable)\n",
				verb, rep.Stored, rep.Files, rep.Lines, rep.AlreadyStored, rep.Unreadable)
			if rep.FirstDay != "" {
				fmt.Fprintf(out, "Backup days read: %s to %s\n", rep.FirstDay, rep.LastDay)
			}
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return fmt.Errorf("stopped; run the command again to continue")
				}
				return err
			}
			if !dryRun && rep.Stored > 0 {
				fmt.Fprintln(out, "The control plane (qpot serve) now classifies the restored events in the background.")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().StringVar(&from, "from", "", "folder of log backups to read (default: the instance's backup/logs)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "read and compare only; store nothing")
	cmd.Flags().BoolVar(&merge, "merge", false, "add the missing events to a database that already holds events")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	return cmd
}
