package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/behaviour"
)

// alertsView is what GET and PUT /api/alerts answer.
type alertsView struct {
	Enabled bool       `json:"enabled"`
	Running bool       `json:"running"`
	Webhook bool       `json:"webhook"`
	Hooks   int        `json:"hooks"`
	Since   *time.Time `json:"since,omitempty"`
	Rules   []struct {
		behaviour.Rule
		Enabled bool `json:"enabled"`
	} `json:"rules"`
	Alerts  []behaviour.Alert `json:"alerts"`
	Problem string            `json:"problem,omitempty"`
}

// alertsAPI calls the running instance's /api/alerts. Tests replace it.
var alertsAPI = func(ctx context.Context, instanceName, method, path string, body any) (*alertsView, error) {
	cfg, id, err := loadCanaryContext(instanceName)
	if err != nil {
		return nil, err
	}
	resp, err := canaryAPI(ctx, cfg, id, method, path, body)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	var v alertsView
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &v, nil
}

func newAlertsCommand() *cobra.Command {
	var instanceName string
	var limit int
	var asJSON bool
	list := func(cmd *cobra.Command, args []string) error {
		if limit < 1 || limit > behaviour.MaxAlerts {
			return fmt.Errorf("--limit must be from 1 to %d", behaviour.MaxAlerts)
		}
		v, err := alertsAPI(cmd.Context(), instanceName, http.MethodGet, fmt.Sprintf("/api/alerts?limit=%d", limit), nil)
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(cmd, v)
		}
		writeAlertRules(cmd, v)
		w := cmd.OutOrStdout()
		fmt.Fprintln(w)
		if len(v.Alerts) == 0 {
			fmt.Fprintln(w, "No behaviour alerts yet.")
			return nil
		}
		fmt.Fprintf(w, "%-20s %-9s %-18s %s\n", "TIME (UTC)", "SEVERITY", "RULE", "WHAT")
		for _, a := range v.Alerts {
			fmt.Fprintf(w, "%-20s %-9s %-18s %s\n", a.Time.UTC().Format("2006-01-02 15:04:05"), termSafe(a.Severity), termSafe(a.Rule), termSafe(a.Title))
			if len(a.Sources) > 0 {
				fmt.Fprintf(w, "%50s from %s\n", "", termSafe(strings.Join(a.Sources, ", ")))
			}
			switch {
			case a.SessionID != "":
				fmt.Fprintf(w, "%50s qpot investigate session %s\n", "", termSafe(a.SessionID))
			case a.Campaign != "":
				fmt.Fprintf(w, "%50s qpot investigate campaign %s\n", "", termSafe(a.Campaign))
			}
		}
		return nil
	}
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Show and change the alerts on what visitors do",
		Long: `Behaviour alerts fire on what a visitor does, where the volume alert only
counts events:

  new-payload        a file with a SHA-256 this instance has not recorded before
  progression        a session that went from discovery to persistence
  credential-reuse   a credential planted in one honeypot, used against another
  shared-playbook    different sources with the same payload, host or commands
  returning-visitor  a source that ran commands, left, and ran commands again

Each thing alerts once. An alert is kept in this list, written to the control
plane's log, posted to alerts.webhook_url when one is set, and handed to the
response.on_behaviour hooks. Rules are on unless turned off, and need the
intelligence worker. What was already there when the rules first ran does not
alert.

  qpot alerts                          the rules and the most recent alerts
  qpot alerts disable returning-visitor
  qpot alerts enable all

The commands talk to the running instance ('qpot up'). The same list and
switches are on the Investigate tab of the web UI. doc/alerts.md has the
webhook payload and the hook variables.`,
		Args: cobra.NoArgs,
		RunE: list,
	}
	cmd.PersistentFlags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().IntVar(&limit, "limit", 30, "how many alerts to show")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	set := func(on bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"enabled": on}
			if args[0] != "all" {
				if !behaviour.IsRule(args[0]) {
					return fmt.Errorf("there is no rule %q: the rules are %s, or 'all'", termSafe(args[0]), ruleNames())
				}
				body["rule"] = args[0]
			}
			v, err := alertsAPI(cmd.Context(), instanceName, http.MethodPut, "/api/alerts", body)
			if err != nil {
				return err
			}
			writeAlertRules(cmd, v)
			return nil
		}
	}
	cmd.AddCommand(
		&cobra.Command{Use: "enable <rule|all>", Short: "Turn a behaviour rule on, or all of them", Args: cobra.ExactArgs(1), RunE: set(true)},
		&cobra.Command{Use: "disable <rule|all>", Short: "Turn a behaviour rule off, or all of them", Args: cobra.ExactArgs(1), RunE: set(false)},
	)
	return cmd
}

func ruleNames() string {
	names := make([]string, 0, len(behaviour.Rules))
	for _, r := range behaviour.Rules {
		names = append(names, r.Name)
	}
	return strings.Join(names, ", ")
}

// writeAlertRules prints the rules and where their alerts go.
func writeAlertRules(cmd *cobra.Command, v *alertsView) {
	w := cmd.OutOrStdout()
	switch {
	case v.Problem != "":
		fmt.Fprintf(w, "Behaviour alerts cannot run: %s\n", termSafe(v.Problem))
	case !v.Enabled:
		fmt.Fprintln(w, "Behaviour alerts are turned off (qpot alerts enable all).")
	case !v.Running:
		fmt.Fprintln(w, "Behaviour alerts are on but cannot run: the intelligence worker is off (intelligence.enabled).")
	default:
		to := []string{"this list", "the control plane's log"}
		if v.Webhook {
			to = append(to, "the webhook")
		}
		if v.Hooks > 0 {
			to = append(to, fmt.Sprintf("%d response hooks", v.Hooks))
		}
		fmt.Fprintf(w, "Behaviour alerts are on. An alert goes to %s.\n", strings.Join(to, ", "))
		if v.Since != nil {
			fmt.Fprintf(w, "Watching since %s UTC; what was there before does not alert.\n", v.Since.UTC().Format("2006-01-02 15:04"))
		}
	}
	fmt.Fprintf(w, "\n%-4s %-18s %-9s %s\n", "ON", "RULE", "SEVERITY", "RAISED WHEN")
	for _, r := range v.Rules {
		on := "no"
		if r.Enabled {
			on = "yes"
		}
		fmt.Fprintf(w, "%-4s %-18s %-9s %s\n", on, termSafe(r.Name), termSafe(r.Severity), termSafe(r.Description))
	}
}
