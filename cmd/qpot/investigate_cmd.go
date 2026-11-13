package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/investigate"
)

// reCaseID is what a session ID or campaign fingerprint may look like.
var reCaseID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// openInvestigation opens what a case of an instance is read from: its
// stored events and sessions, its canary trips and its captured command
// output. It reads the config only: no QPot ID is loaded or printed. Tests
// replace it.
var openInvestigation = func(ctx context.Context, name string) (investigate.Reader, investigate.Options, func(), error) {
	var opts investigate.Options
	cfg, err := config.Load(name)
	if err != nil {
		return nil, opts, nil, fmt.Errorf("failed to load config: %w", err)
	}
	db, err := database.New(cfg.DatabaseClient())
	if err != nil {
		return nil, opts, nil, fmt.Errorf("failed to construct database driver: %w", err)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.Connect(connectCtx); err != nil {
		return nil, opts, nil, fmt.Errorf("failed to connect to the database of instance %q (is it running?): %w", name, err)
	}
	if cfg.Canary.Enabled {
		// The trips as the running instance last saved them. A store that
		// cannot be read costs the case its canary steps, not the case.
		if store, err := canary.NewStore(cfg.DataPath, cfg.Canary.MaxTrips); err == nil {
			opts.Trips = store.Trips(0)
		} else {
			fmt.Fprintf(os.Stderr, "warning: canary trips are not shown: %v\n", err)
		}
	}
	opts.Output = instance.SSHCapturedOutput(cfg)
	return db, opts, func() { _ = db.Close() }, nil
}

func newInvestigateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "investigate",
		Short: "Follow one session or campaign through everything recorded about it",
		Long: `Put together what QPot recorded about one session or one campaign, in the
order it happened:

  connection -> credentials tried -> commands run -> files transferred ->
  canaries tripped -> related sessions

Every line states something a stored record shows, and ends with that
record's reference in [brackets]. A campaign's case names the evidence its
sessions share (a payload, a download host, a command sequence) and the
records that show it in each session. Whatever is missing is listed under
Gaps: values that were cut, lines the collector discarded, output that was
not captured, events past the limit or removed by retention.

  qpot investigate list
  qpot investigate session <session-id>
  qpot investigate campaign <fingerprint>
  qpot investigate export session <session-id> --out case.zip
  qpot investigate verify case.zip

A case reads the instance's database directly, so the instance must be up;
'qpot serve' need not run. The same view is the Investigate tab of the web
UI. doc/investigate.md describes a case and an evidence bundle in full.`,
	}
	cmd.AddCommand(newInvestigateListCommand(), newInvestigateCaseCommand("session"), newInvestigateCaseCommand("campaign"),
		newInvestigateExportCommand(), newInvestigateVerifyCommand())
	return cmd
}

func newInvestigateListCommand() *cobra.Command {
	var instanceName string
	var limit int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the most recent sessions and the campaigns they form",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > investigate.MaxList {
				return fmt.Errorf("--limit must be from 1 to %d", investigate.MaxList)
			}
			db, _, done, err := openInvestigation(cmd.Context(), instanceName)
			if err != nil {
				return err
			}
			defer done()
			listing, err := investigate.List(cmd.Context(), db, limit)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(cmd, listing)
			}
			return investigate.WriteListing(cmd.OutOrStdout(), listing)
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().IntVar(&limit, "limit", 30, "how many sessions and campaigns to list")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// buildCase reads the case of one session or campaign of an instance.
func buildCase(ctx context.Context, instanceName, kind, id string, maxEvents int, noOutput bool) (*investigate.Case, error) {
	if !reCaseID.MatchString(id) {
		return nil, fmt.Errorf("%q is not a %s: copy one from 'qpot investigate list'", termSafe(id), map[string]string{"session": "session ID", "campaign": "campaign fingerprint"}[kind])
	}
	if maxEvents < 1 || maxEvents > investigate.HardMaxEvents {
		return nil, fmt.Errorf("--max-events must be from 1 to %d", investigate.HardMaxEvents)
	}
	db, opts, done, err := openInvestigation(ctx, instanceName)
	if err != nil {
		return nil, err
	}
	defer done()
	opts.MaxEvents = maxEvents
	if noOutput {
		opts.Output = nil
	}
	var c *investigate.Case
	if kind == "session" {
		c, err = investigate.SessionCaseFor(ctx, db, id, opts)
	} else {
		c, err = investigate.CampaignCaseFor(ctx, db, id, opts)
	}
	if errors.Is(err, investigate.ErrNotFound) {
		return nil, fmt.Errorf("instance %q has no %s %s among its most recent %d sessions ('qpot investigate list' shows what there is)",
			instanceName, kind, id, investigate.SessionScan)
	}
	if err != nil {
		return nil, err
	}
	c.Instance = instanceName
	return c, nil
}

func newInvestigateCaseCommand(kind string) *cobra.Command {
	var instanceName string
	var maxEvents int
	var asJSON, noOutput bool
	arg, short := "<session-id>", "Show one session: its timeline, files, evidence, related sessions and gaps"
	if kind == "campaign" {
		arg, short = "<fingerprint>", "Show one campaign: its sessions, and the evidence that links them"
	}
	cmd := &cobra.Command{
		Use:   kind + " " + arg,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := buildCase(cmd.Context(), instanceName, kind, args[0], maxEvents, noOutput)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(cmd, c)
			}
			return investigate.WriteText(cmd.OutOrStdout(), c)
		},
	}
	caseFlags(cmd, &instanceName, &maxEvents, &noOutput)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the whole case as JSON, records included")
	return cmd
}

func caseFlags(cmd *cobra.Command, instanceName *string, maxEvents *int, noOutput *bool) {
	cmd.Flags().StringVarP(instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().IntVar(maxEvents, "max-events", investigate.DefaultMaxEvents, "how many events to read; a campaign's sessions share them")
	cmd.Flags().BoolVar(noOutput, "no-output", false, "leave out what captured commands printed")
}

func newInvestigateExportCommand() *cobra.Command {
	var instanceName, out string
	var maxEvents int
	var noOutput bool
	cmd := &cobra.Command{
		Use:   "export (session|campaign) <id>",
		Short: "Write a case as an evidence bundle: records, timeline, output and a manifest of hashes",
		Long: `Write the case of one session or campaign as an evidence bundle: a zip archive
with the case, every record it cites, its timeline as text, what captured
commands printed, and MANIFEST.sha256 with the hash of each file.

The bundle's own SHA-256 is printed. Keep it apart from the bundle if you may
have to show later that the bundle is the one you made. 'qpot investigate
verify' checks a bundle; so does 'sha256sum -c MANIFEST.sha256' inside it.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind := args[0]
			if kind != "session" && kind != "campaign" {
				return fmt.Errorf("export a session or a campaign, not %q", termSafe(kind))
			}
			if out == "" {
				return errors.New("name the file to write with --out")
			}
			c, err := buildCase(cmd.Context(), instanceName, kind, args[1], maxEvents, noOutput)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			manifest, err := investigate.WriteBundle(&buf, c)
			if err != nil {
				return err
			}
			// Never over a file that is there: a bundle is evidence.
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				if errors.Is(err, os.ErrExist) {
					return fmt.Errorf("%s exists already: choose another name", out)
				}
				return err
			}
			if _, err := f.Write(buf.Bytes()); err != nil {
				_ = f.Close()
				_ = os.Remove(out)
				return err
			}
			if err := f.Close(); err != nil {
				_ = os.Remove(out)
				return err
			}
			sum := sha256.Sum256(buf.Bytes())
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Wrote %s: %d files, %d records, %d gaps\n", out, len(manifest)+1, len(c.Records), len(c.Gaps))
			fmt.Fprintf(w, "SHA-256 %s\n", hex.EncodeToString(sum[:]))
			return nil
		},
	}
	caseFlags(cmd, &instanceName, &maxEvents, &noOutput)
	cmd.Flags().StringVarP(&out, "out", "o", "", "the bundle to write (it must not exist)")
	return cmd
}

func newInvestigateVerifyCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify <bundle.zip>",
		Short: "Check an evidence bundle: file hashes, record references and citations",
		Long: `Check an evidence bundle without an instance or a database: every file has
the hash its manifest gives, every record still has the reference it is cited
by, and every record the case cites is in the bundle.

The exit status is 0 for a whole bundle and 1 for one with problems.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				return err
			}
			rep, err := investigate.VerifyBundle(f, info.Size())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				if err := printJSON(cmd, rep); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(w, "%s %s: %d files, %d records, %d cited\n", termSafe(rep.Kind), termSafe(rep.ID), rep.Files, rep.Records, rep.Cited)
				for _, p := range rep.Problems {
					fmt.Fprintf(w, "  problem: %s\n", termSafe(p))
				}
				if rep.OK() {
					fmt.Fprintln(w, "The bundle is whole.")
				}
			}
			if !rep.OK() {
				return fmt.Errorf("the bundle has %d problems", len(rep.Problems))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
