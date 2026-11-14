package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/cluster"
)

// fleetAnswer is what GET /api/fleet answers.
type fleetAnswer struct {
	Clustered bool   `json:"clustered"`
	Live      bool   `json:"live"`
	Cluster   string `json:"cluster,omitempty"`
	cluster.FleetView
}

// fleetAPI reads the running instance's /api/fleet. Tests replace it.
var fleetAPI = func(ctx context.Context, instanceName string) (*fleetAnswer, error) {
	cfg, id, err := loadCanaryContext(instanceName)
	if err != nil {
		return nil, err
	}
	resp, err := canaryAPI(ctx, cfg, id, http.MethodGet, "/api/fleet", nil)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	var v fleetAnswer
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &v, nil
}

// fleetNow is the clock "ago" is measured from. Tests replace it.
var fleetNow = time.Now

func fleetAgo(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	d := fleetNow().Sub(*t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func newFleetCommand() *cobra.Command {
	var instanceName string
	var asJSON, check bool
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Show every sensor of the cluster in one place",
		Long: `Each sensor keeps its own events and its own dashboard. The sensors of a
cluster also tell each other a little about themselves every 30 seconds: the
version they run, the honeypots turned on, how many events they recorded, the
behaviour alerts of the last day and the SHA-256 of the files they captured
this week. 'qpot fleet' puts that in one place:

  - a row for each sensor, and what is wrong with the ones that need a look
    (offline, no report, no events in a day, its database down, another
    version)
  - the payloads and source addresses more than one sensor saw
  - the sensors' behaviour alerts in one list, the newest first

A sensor in no cluster is a fleet of one. To look into something a sensor
reports, open that sensor: the events never leave it.

  qpot fleet
  qpot fleet --check     exit with status 1 when a sensor needs a look
  qpot fleet --json

The command talks to the running instance ('qpot up'). The same view is on
the Pairing tab of the web UI. 'qpot cluster' pairs the sensors;
doc/clustering.md has the details.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := fleetAPI(cmd.Context(), instanceName)
			if err != nil {
				return err
			}
			if asJSON {
				if err := printJSON(cmd, v); err != nil {
					return err
				}
			} else {
				writeFleet(cmd, v)
			}
			if check && v.Totals.NeedAttention > 0 {
				return fmt.Errorf("%d of %d sensors need a look", v.Totals.NeedAttention, v.Totals.Sensors)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().BoolVar(&check, "check", false, "exit with status 1 when a sensor needs a look")
	return cmd
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// writeFleet prints the fleet view. Everything a sensor said about itself
// is another machine's text: it goes through termSafe.
func writeFleet(cmd *cobra.Command, v *fleetAnswer) {
	w := cmd.OutOrStdout()
	t := v.Totals
	switch {
	case !v.Clustered:
		fmt.Fprintln(w, "This sensor is in no cluster, so it is a fleet of one ('qpot cluster init' and 'qpot cluster join' pair sensors).")
	default:
		look := "none needs a look"
		if t.NeedAttention > 0 {
			look = plural(t.NeedAttention, "needs a look", "need a look")
		}
		fmt.Fprintf(w, "Cluster %s: %s, %d online, %s.\n", termSafe(v.Cluster), plural(t.Sensors, "sensor", "sensors"), t.Online, look)
		if !v.Live {
			fmt.Fprintln(w, "This control plane does not run the cluster, so it knows the other sensors only by name.")
		}
	}
	fmt.Fprintf(w, "%d events in the last hour, %d in the last day, %s in the last day.\n\n", t.EventsHour, t.EventsDay, plural(t.Alerts, "behaviour alert", "behaviour alerts"))

	fmt.Fprintf(w, "  %-20s %-9s %-10s %-9s %9s %10s %6s  %s\n", "SENSOR", "STATE", "VERSION", "HONEYPOTS", "EVENTS 1H", "EVENTS 24H", "ALERTS", "LAST EVENT")
	for _, s := range v.Sensors {
		mark, state, version := " ", termSafe(s.Status), termSafe(s.Version)
		if s.Local {
			mark = "*"
		}
		if s.Online {
			state = "online"
		}
		if version == "" {
			version = "-"
		}
		fmt.Fprintf(w, "%s %-20s %-9s %-10s %-9d %9d %10d %6d  %s\n", mark, termSafe(s.Name), state, version, len(s.Honeypots), s.EventsHour, s.EventsDay, s.Alerts, fleetAgo(s.LastEvent))
		if len(s.Attention) > 0 {
			fmt.Fprintf(w, "    needs a look: %s\n", termSafe(strings.Join(s.Attention, "; ")))
		}
	}
	fmt.Fprintln(w, "  (* this sensor)")

	if len(v.Shared) > 0 {
		fmt.Fprintf(w, "\nSeen by more than one sensor\n  %-8s %-64s %s\n", "KIND", "VALUE", "SENSORS")
		for _, s := range v.Shared {
			names := make([]string, len(s.Sensors))
			for i, n := range s.Sensors {
				names[i] = termSafe(n)
			}
			line := fmt.Sprintf("  %-8s %-64s %s", termSafe(s.Kind), termSafe(s.Value), strings.Join(names, ", "))
			if s.Kind == "source" {
				line += fmt.Sprintf(" (%d events in the last hour)", s.Events)
			}
			fmt.Fprintln(w, line)
		}
	} else if v.Clustered && v.Live {
		fmt.Fprintln(w, "\nNo payload or source was seen by more than one sensor.")
	}

	if len(v.Alerts) > 0 {
		fmt.Fprintf(w, "\nBehaviour alerts of the last day\n  %-20s %-20s %-9s %-18s %s\n", "TIME (UTC)", "SENSOR", "SEVERITY", "RULE", "WHAT")
		for _, a := range v.Alerts {
			fmt.Fprintf(w, "  %-20s %-20s %-9s %-18s %s\n", a.Time.UTC().Format("2006-01-02 15:04:05"), termSafe(a.Sensor), termSafe(a.Severity), termSafe(a.Rule), termSafe(a.Title))
			if len(a.Sources) > 0 {
				fmt.Fprintf(w, "  %71s from %s\n", "", termSafe(strings.Join(a.Sources, ", ")))
			}
		}
		fmt.Fprintln(w, "  To look into one, run 'qpot alerts' and 'qpot investigate' on the sensor that raised it.")
	}
}
