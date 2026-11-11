package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/engagement"
)

// reHoneypotName is what a --honeypot value may look like.
var reHoneypotName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// engagementOutput is what `qpot engagement --json` prints.
type engagementOutput struct {
	Reports []*engagement.Report `json:"reports"`
	// Comparisons set the first report against each of the others: the
	// exposure check, every metric with its intervals, test and verdict, and
	// the analysis of the sources both saw.
	Comparisons []engagement.Comparison `json:"comparisons,omitempty"`
}

// openInstanceEvents opens the stored events of an instance. It returns the
// reader and the function that closes it. It reads the config only: no QPot
// ID is loaded or printed. Tests replace it.
var openInstanceEvents = func(ctx context.Context, name string) (engagement.EventReader, func(), error) {
	cfg, err := config.Load(name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}
	db, err := database.New(cfg.DatabaseClient())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to construct database driver: %w", err)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.Connect(connectCtx); err != nil {
		return nil, nil, fmt.Errorf("failed to connect to the database of instance %q (is it running?): %w", name, err)
	}
	return db, func() { _ = db.Close() }, nil
}

// checkAgainst validates the --against instances the way the root command
// validates -i: each must be a valid name of an instance that exists. They
// are compared with the instance named by -i, so that one must be given, and
// no instance may be named twice.
func checkAgainst(primary string, against []string) error {
	if len(against) == 0 {
		return nil
	}
	if primary == "" {
		return errors.New("--against compares with the instance named by -i: name that instance too")
	}
	seen := map[string]bool{primary: true}
	for _, name := range against {
		if err := validateInstanceName(name); err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("--against %s: that instance is already being measured", name)
		}
		seen[name] = true
		if _, err := os.Stat(config.Default(name).ConfigPath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("instance %q does not exist (create it with: qpot setup -i %s)", name, name)
		}
	}
	return nil
}

func newEngagementCommand() *cobra.Command {
	var (
		instanceName string
		since        string
		honeypots    []string
		asJSON       bool
		logs         []string
		labels       []string
		against      []string
	)
	cmd := &cobra.Command{
		Use:   "engagement",
		Short: "Measure how far visitors go: logins, commands, session length, payloads",
		Long: `Measure visitor engagement from stored events: how many sessions logged in,
ran a command and fetched a payload, how long and how deep the sessions were,
how varied the commands were, how often a session ended right after a
fingerprint probe, how many sources came back, and how many payload hashes,
download URLs, credential pairs and ATT&CK techniques the sessions left.

--against names another instance, and --cowrie-log the JSON log of any Cowrie
deployment (stock Cowrie, T-Pot). The same numbers are computed for each and
set side by side with the first report, which is the instance named by -i when
there is one.

A comparison starts with an exposure check: sessions, source addresses and
observation period of each side, and how many source addresses both saw. After
the table it gives a 95% interval for every share and median, a verdict for
each difference ("clear difference", "no clear difference" or "too few to
compare", at the 5% level after Holm's correction), and an analysis of the
sources that visited both sides. Run both deployments with the same exposure
over the same period before reading anything into a difference:
doc/effectiveness.md says how, defines every metric and explains how to read
a comparison.

  qpot engagement -i sensor1
  qpot engagement -i sensor1 --since 30d --honeypot cowrie
  qpot engagement -i treat --against control --honeypot cowrie
  qpot engagement -i sensor1 --honeypot cowrie --cowrie-log /var/log/cowrie/cowrie.json --label stock
  qpot engagement --cowrie-log a.json --cowrie-log b.json --json

With only --cowrie-log the command needs no instance and no Docker. A log is
read whole unless --since is given; every instance is read over --since
(default 7d) and limited by --honeypot.`,
		Args: cobra.NoArgs,
		// The root command requires -i to name an existing instance. Here an
		// instance is optional, so the check runs only when one is named.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if instanceName != "" {
				if err := checkInstanceFlag(cmd, args); err != nil {
					return err
				}
			}
			return checkAgainst(instanceName, against)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if instanceName == "" && len(logs) == 0 {
				return errors.New("name an instance with -i, a Cowrie log with --cowrie-log, or both")
			}
			if len(labels) > len(logs) {
				return errors.New("--label names a --cowrie-log file: there are more labels than logs")
			}
			for _, hp := range honeypots {
				if !reHoneypotName.MatchString(hp) {
					return fmt.Errorf("invalid honeypot name %q", hp)
				}
			}
			window, err := parseSince(since)
			if err != nil {
				return err
			}
			until := time.Now().UTC()
			from := until.Add(-window)

			var reports []*engagement.Report
			instances := against
			if instanceName != "" {
				instances = append([]string{instanceName}, against...)
			}
			for _, name := range instances {
				rep, err := instanceEngagement(cmd.Context(), name, from, until, honeypots)
				if err != nil {
					return err
				}
				reports = append(reports, rep)
			}
			for i, path := range logs {
				label := filepath.Base(path)
				if i < len(labels) && strings.TrimSpace(labels[i]) != "" {
					label = strings.TrimSpace(labels[i])
				}
				var limit *time.Time
				if cmd.Flags().Changed("since") {
					limit = &from
				}
				rep, err := logEngagement(path, termSafe(label), limit, until)
				if err != nil {
					return err
				}
				reports = append(reports, rep)
			}

			out := cmd.OutOrStdout()
			if asJSON {
				res := engagementOutput{Reports: reports}
				for _, other := range reports[1:] {
					res.Comparisons = append(res.Comparisons, engagement.Compare(*reports[0], *other))
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			return engagement.WriteText(out, reports)
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "", "instance to measure")
	cmd.Flags().StringVar(&since, "since", "7d", "how far back to read: a number of days (7d), weeks (2w) or a duration (36h)")
	cmd.Flags().StringArrayVar(&against, "against", nil, "another instance to measure and compare with the one named by -i (repeatable)")
	cmd.Flags().StringSliceVar(&honeypots, "honeypot", nil, "limit every instance to these honeypots (repeat or separate with commas)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().StringArrayVar(&logs, "cowrie-log", nil, "a Cowrie JSON log to measure the same way (repeatable)")
	cmd.Flags().StringArrayVar(&labels, "label", nil, "name for the --cowrie-log file at the same position (default: its file name)")
	return cmd
}

// parseSince reads a look-back window: whole days ("7d"), whole weeks ("2w")
// or a Go duration ("36h").
func parseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	var d time.Duration
	switch {
	case strings.HasSuffix(s, "d") || strings.HasSuffix(s, "w"):
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil || n <= 0 || n > 3660 {
			return 0, fmt.Errorf("invalid --since %q: use for example 7d, 2w or 36h", s)
		}
		d = time.Duration(n) * 24 * time.Hour
		if strings.HasSuffix(s, "w") {
			d *= 7
		}
	default:
		var err error
		if d, err = time.ParseDuration(s); err != nil || d <= 0 {
			return 0, fmt.Errorf("invalid --since %q: use for example 7d, 2w or 36h", s)
		}
	}
	return d, nil
}

// instanceEngagement reads an instance's stored events from its database.
func instanceEngagement(ctx context.Context, name string, from, until time.Time, honeypots []string) (*engagement.Report, error) {
	db, closeDB, err := openInstanceEvents(ctx, name)
	if err != nil {
		return nil, err
	}
	defer closeDB()

	q := engagement.DBQuery{Since: from, Until: until, Honeypots: honeypots}
	rep, err := engagement.Compute(termSafe(name), func(emit func(engagement.Event) bool) error {
		_, err := engagement.ReadDatabase(ctx, db, q, emit)
		return err
	}, engagement.Options{})
	if err != nil {
		return nil, err
	}
	rep.Source = "qpot-instance"
	rep.HoneypotFilter = honeypots
	return rep, nil
}

// logEngagement reads a Cowrie JSON log. With from set, events outside
// [from, until] are left out and counted.
func logEngagement(path, label string, from *time.Time, until time.Time) (*engagement.Report, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the log to read
	if err != nil {
		return nil, fmt.Errorf("cannot read the Cowrie log: %w", err)
	}
	defer f.Close()

	var stats engagement.LogStats
	var outside int64
	rep, err := engagement.Compute(label, func(emit func(engagement.Event) bool) error {
		var err error
		stats, err = engagement.ReadCowrieLog(f, func(e engagement.Event) bool {
			if from != nil && (e.Time.Before(*from) || e.Time.After(until)) {
				outside++
				return true
			}
			return emit(e)
		})
		return err
	}, engagement.Options{})
	if err != nil {
		return nil, fmt.Errorf("cannot read the Cowrie log %s: %w", termSafe(path), err)
	}
	stats.OutsideWindow = outside
	rep.Source = "cowrie-log"
	rep.Input.Log = &stats
	return rep, nil
}
