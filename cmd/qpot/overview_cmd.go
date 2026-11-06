package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/overview"
	"github.com/spf13/cobra"
)

// newOverviewCommand prints the local overview of one instance, or a summary of
// every instance on this host. Everything is read locally: the instance's own
// API (QPot-ID authenticated, loopback) or, when its control plane is not
// running, the instance database directly.
func newOverviewCommand() *cobra.Command {
	var (
		instanceName string
		all          bool
		asJSON       bool
	)
	cmd := &cobra.Command{
		Use:   "overview",
		Short: "Show host resources, honeypot activity and recent events (local)",
		Long: `Show an at-a-glance overview of an instance: host CPU / memory / disk /
process load, events and unique attackers over the last 24 hours, per-honeypot
activity, cluster membership and the latest events with a severity.

The same data is on the dashboard's Overview tab and at GET /api/overview.
Nothing is sent off the host.

  qpot overview              # the default instance
  qpot overview -i sensor1
  qpot overview --all        # one line per instance on this host
  qpot overview --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if all {
				return overviewAll(ctx, cmd.OutOrStdout(), asJSON)
			}
			// Read-only: never create an instance or mint a QPot ID here.
			if _, err := os.Stat(config.Default(instanceName).ConfigPath); errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("instance %q does not exist (create one with: qpot setup -i %s)", instanceName, instanceName)
			}
			cfg, qpotID, err := loadCanaryContext(instanceName)
			if err != nil {
				return err
			}
			ov, live, err := fetchOverview(ctx, cfg, qpotID)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(ov)
			}
			printOverview(cmd.OutOrStdout(), ov, live)
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().BoolVar(&all, "all", false, "summarise every instance on this host")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// fetchOverview asks the instance's running control plane for its overview.
// When the control plane is not running it builds the overview here, reading
// the database directly (live=false).
func fetchOverview(ctx context.Context, cfg *config.Config, qpotID string) (*overview.Overview, bool, error) {
	if runningServePID(cfg) != 0 {
		ov, err := apiOverview(ctx, cfg, qpotID)
		if err == nil {
			return ov, true, nil
		}
	}
	var db database.Database
	if d, err := database.New(cfg.DatabaseClient()); err == nil {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if d.Connect(dctx) == nil {
			db = d
			defer d.Close()
		}
		cancel()
	}
	bctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return overview.Build(bctx, cfg, db, nil, version), false, nil
}

func apiOverview(ctx context.Context, cfg *config.Config, qpotID string) (*overview.Overview, error) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, localBaseURL(cfg)+"/api/overview", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-QPot-ID", qpotID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("overview: %s", resp.Status)
	}
	var ov overview.Overview
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&ov); err != nil {
		return nil, fmt.Errorf("overview: %w", err)
	}
	// Another instance (or anything else) answering on this port is not us.
	if ov.Instance != cfg.InstanceName {
		return nil, fmt.Errorf("overview: port %d answered as instance %q", cfg.WebUI.Port, ov.Instance)
	}
	return &ov, nil
}

func printOverview(w io.Writer, ov *overview.Overview, live bool) {
	src := "live"
	if !live {
		src = "control plane not running; read from the database"
	}
	fmt.Fprintf(w, "Instance %s on %s (%s/%s, qpot %s) - %s\n\n", ov.Instance, ov.Hostname, ov.OS, ov.Arch, ov.Version, src)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, g := range []struct {
		name string
		g    overview.Gauge
	}{{"CPU", ov.CPU}, {"Memory", ov.Memory}, {"Disk", ov.Disk}, {"Processes", ov.Processes}} {
		fmt.Fprintf(tw, "%s\t%3d%%\t%s\n", g.name, g.g.Pct, g.g.Caption)
	}
	tw.Flush()

	dbState := "unreachable"
	if ov.DatabaseOK {
		dbState = "ok"
	}
	fmt.Fprintf(w, "\nDatabase %s (%s): %d events and %d unique IPs in the last 24h (%.2f/s)\n",
		ov.Database, dbState, ov.Events24h, ov.UniqueIPs24h, ov.EventsPerSec)
	if ov.Cluster != nil {
		fmt.Fprintf(w, "Cluster %s: %d/%d nodes healthy\n", ov.Cluster.Name, ov.Cluster.Healthy, ov.Cluster.Nodes)
	}

	fmt.Fprintln(w, "\nHoneypots")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, hp := range ov.Honeypots {
		if !hp.Enabled && hp.Hits24h == 0 {
			continue
		}
		state := "off"
		if hp.Enabled {
			state = "on"
		}
		fmt.Fprintf(tw, "  %s\t%s\tport %d\t%d hits/24h\n", hp.Name, state, hp.Port, hp.Hits24h)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nRecent events")
	if len(ov.RecentEvents) == 0 {
		fmt.Fprintln(w, "  none yet")
		return
	}
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, e := range ov.RecentEvents {
		tech := ""
		if e.Technique != "" {
			tech = "[" + e.Technique + "]"
		}
		// Event fields are attacker input; the API strips C0 controls, but not
		// C1 ones or bidi overrides, and this may be another program's answer.
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", e.Time.Local().Format("Jan 02 15:04:05"),
			termSafe(strings.ToUpper(e.Severity)), termSafe(e.Honeypot), termSafe(e.SourceIP),
			truncate(termSafe(e.Summary), 70), termSafe(tech))
	}
	tw.Flush()
}

// instanceSummary is one row of `qpot overview --all`.
type instanceSummary struct {
	Instance     string `json:"instance"`
	Containers   string `json:"containers"`
	ControlPlane string `json:"control_plane"`
	WebUI        string `json:"web_ui"`
	Honeypots    int    `json:"honeypots_enabled"`
	Events24h    int64  `json:"events_24h"`
	UniqueIPs24h int64  `json:"unique_ips_24h"`
	LastEvent    string `json:"last_event,omitempty"`
	Error        string `json:"error,omitempty"`
}

func overviewAll(ctx context.Context, w io.Writer, asJSON bool) error {
	infos, err := instance.List()
	if err != nil {
		return fmt.Errorf("failed to list instances: %w", err)
	}
	rows := make([]instanceSummary, 0, len(infos))
	for _, inf := range infos {
		row := instanceSummary{Instance: inf.Name, Containers: "stopped", ControlPlane: "stopped"}
		if inf.Running {
			row.Containers = "running"
		}
		cfg, err := config.Load(inf.Name)
		if err != nil {
			row.Error = err.Error()
			rows = append(rows, row)
			continue
		}
		row.WebUI = localBaseURL(cfg)
		for _, hp := range cfg.SnapshotHoneypots() {
			if hp.Enabled {
				row.Honeypots++
			}
		}
		if runningServePID(cfg) != 0 {
			row.ControlPlane = "running"
		}
		if inf.Running {
			id, err := instance.LoadID(inf.Name)
			if err != nil || id == nil {
				row.Error = "no QPot ID"
			} else if ov, _, err := fetchOverview(ctx, cfg, id.ID); err != nil {
				row.Error = err.Error()
			} else {
				row.Events24h, row.UniqueIPs24h = ov.Events24h, ov.UniqueIPs24h
				if len(ov.RecentEvents) > 0 {
					row.LastEvent = ov.RecentEvents[0].Time.Local().Format(time.RFC3339)
				}
				if !ov.DatabaseOK {
					row.Error = "database unreachable"
				}
			}
		}
		rows = append(rows, row)
	}

	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "No QPot instances found (create one with: qpot setup)")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INSTANCE\tCONTAINERS\tCONTROL PLANE\tHONEYPOTS\tEVENTS/24H\tIPS/24H\tLAST EVENT\tWEB UI\tNOTE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\n", r.Instance, r.Containers, r.ControlPlane,
			r.Honeypots, r.Events24h, r.UniqueIPs24h, dash(r.LastEvent), dash(r.WebUI), r.Error)
	}
	return tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
