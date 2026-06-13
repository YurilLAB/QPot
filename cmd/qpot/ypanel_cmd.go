package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/ypanel"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newYpanelCommand wires the ypanel operator-console integration to the CLI.
// ypanel is Yuril Security's unified control panel; this integration is QPot's
// phone-home agent to its operator plane (the DireC activation worker). `setup`
// records the enrolment a host operator pasted from the panel, `status` shows
// the wire + whether the host is ready to report, and `test` performs a single
// live snapshot push so misconfigurations are caught before `qpot up`.
func newYpanelCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ypanel",
		Short: "Connect this QPot instance to the ypanel operator console",
		Long: `Manage QPot's phone-home agent to ypanel (Yuril Security's unified
operator console). Enrol the host in the panel (QPot -> Set up a host) to get an
instance id + a one-time enrollment token, then:

  qpot ypanel setup    # record the enrolment and turn the agent on
  qpot ypanel test     # push one live snapshot and report the result
  qpot ypanel status   # show the wire and whether the host is ready to report

The agent runs automatically inside 'qpot up' once configured. The per-instance
QPot-ID never leaves the host; the agent authenticates with a cached license JWS
plus the enrollment token. See docs/ypanel.md for the full model.`,
	}
	cmd.AddCommand(newYpanelSetupCommand())
	cmd.AddCommand(newYpanelTestCommand())
	cmd.AddCommand(newYpanelStatusCommand())
	return cmd
}

func newYpanelSetupCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Record the panel enrolment and enable the phone-home agent",
		Long:  "Walks through the ypanel agent settings and writes them into the instance config. Run after enrolling the host in the panel.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateInstanceName(instanceName); err != nil {
				return err
			}
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			fmt.Println("QPot -> ypanel operator console — interactive setup")
			fmt.Println("Enrol the host in the panel first (QPot -> Set up a host) to get the")
			fmt.Println("instance id and one-time enrollment token. Press Enter to keep [brackets].")
			fmt.Println()

			cfg.Ypanel.Base = readLineWithDefault("ypanel worker base URL",
				firstNonEmpty(cfg.Ypanel.Base, "https://ypanel.yurillab.dev"))
			if !strings.HasPrefix(cfg.Ypanel.Base, "http://") && !strings.HasPrefix(cfg.Ypanel.Base, "https://") {
				return fmt.Errorf("base must start with http:// or https://")
			}

			cfg.Ypanel.InstanceID = readLineWithDefault("Instance id (qp_...)", cfg.Ypanel.InstanceID)
			if cfg.Ypanel.InstanceID == "" {
				return fmt.Errorf("instance id is required; aborting")
			}

			fmt.Print("Enrollment token (yp_..., input hidden, Enter to keep current): ")
			tokBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read enrollment token: %w", err)
			}
			if entered := strings.TrimSpace(string(tokBytes)); entered != "" {
				cfg.Ypanel.EnrollToken = entered
			}
			if cfg.Ypanel.EnrollToken == "" {
				return fmt.Errorf("enrollment token is required; aborting")
			}

			cfg.Ypanel.LicenseJWSPath = readLineWithDefault(
				"License JWS path (blank = probe well-known activation paths)", cfg.Ypanel.LicenseJWSPath)
			cfg.Ypanel.Region = readLineWithDefault("Region label (cosmetic)", cfg.Ypanel.Region)

			cfg.Ypanel.Enabled = true
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Println()
			fmt.Println("[OK] ypanel agent configured.")
			fmt.Printf("     Config file: %s\n", cfg.ConfigPath)
			if _, jErr := ypanel.ResolveLicenseJWS(cfg.Ypanel); jErr != nil {
				fmt.Printf("     [WARN] license JWS not found yet: %v\n", jErr)
				fmt.Println("            Activate the Yuril/DireC daemon or set a license_jws_path.")
			}
			fmt.Println("     Run 'qpot ypanel test' to push one live snapshot.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

func newYpanelTestCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Push one live snapshot to the operator plane and report the result",
		Long: `Loads the instance config, builds the agent, and pushes a single snapshot
to the ypanel worker. Reports readiness gaps (missing enrolment / license JWS)
and distinguishes auth/validation rejections from unreachable-host errors.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateInstanceName(instanceName); err != nil {
				return err
			}
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			if !cfg.Ypanel.Enabled {
				return fmt.Errorf("ypanel agent is disabled in config; run 'qpot ypanel setup' first")
			}
			qpotID, _ := instance.LoadID(instanceName)
			if qpotID != nil {
				cfg.QPotID = qpotID.ID
			}

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}
			ag, err := ypanel.New(cfg, mgr, version)
			if err != nil {
				return fmt.Errorf("agent init failed: %w", err)
			}
			if ag == nil {
				return fmt.Errorf("agent is nil; double-check ypanel.enabled in config")
			}
			defer ag.Close()
			if !ag.Ready() {
				fmt.Println("[FAIL] Agent is not ready to report. Missing one of:")
				fmt.Printf("       - instance id set:      %v\n", strings.TrimSpace(cfg.Ypanel.InstanceID) != "")
				fmt.Printf("       - enrollment token set: %v\n", strings.TrimSpace(cfg.Ypanel.EnrollToken) != "")
				_, jErr := ypanel.ResolveLicenseJWS(cfg.Ypanel)
				fmt.Printf("       - license JWS resolved: %v\n", jErr == nil)
				if jErr != nil {
					fmt.Printf("         (%v)\n", jErr)
				}
				return fmt.Errorf("not ready")
			}

			fmt.Printf("Pushing a snapshot to %s ...\n", cfg.Ypanel.Base)
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()
			status, err := ag.PushOnce(ctx)
			if err != nil {
				fmt.Println("[FAIL] Snapshot push failed.")
				fmt.Printf("       HTTP %d: %v\n", status, err)
				fmt.Println("       Hints:")
				fmt.Println("         - 401: stale/invalid license JWS or wrong enrollment token.")
				fmt.Println("         - 400: snapshot validation rejected (check the worker contract).")
				fmt.Println("         - 410: licence cancelled/expired; re-activate the daemon.")
				fmt.Println("         - connection refused/timeout: check ypanel.base and the network.")
				return err
			}
			fmt.Printf("[OK] Snapshot accepted (HTTP %d). The host is now live in ypanel.\n", status)
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

func newYpanelStatusCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the ypanel agent configuration and host readiness",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateInstanceName(instanceName); err != nil {
				return err
			}
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			id, _ := instance.LoadID(instanceName)

			fmt.Println("ypanel operator-console integration")
			fmt.Println("===================================")
			fmt.Printf("Instance:        %s\n", cfg.InstanceName)
			if id != nil {
				fmt.Printf("QPot ID:         %s (local only, never sent)\n", id.ID)
			}
			fmt.Println()
			fmt.Println("Phone-home agent (qpot -> ypanel operator plane)")
			fmt.Printf("  Enabled:         %v\n", cfg.Ypanel.Enabled)
			fmt.Printf("  Worker base:     %s\n", maskIfEmpty(cfg.Ypanel.Base))
			fmt.Printf("  Instance id:     %s\n", maskIfEmpty(cfg.Ypanel.InstanceID))
			fmt.Printf("  Enroll token:    %s\n", boolMask(strings.TrimSpace(cfg.Ypanel.EnrollToken) != ""))
			jws, jErr := ypanel.ResolveLicenseJWS(cfg.Ypanel)
			fmt.Printf("  License JWS:     %s\n", boolMask(jErr == nil && jws != ""))
			if jErr != nil {
				fmt.Printf("                   (%v)\n", jErr)
			}
			fmt.Printf("  Region:          %s\n", maskIfEmpty(cfg.Ypanel.Region))
			fmt.Printf("  Push interval:   %s\n", cfg.Ypanel.PushInterval)
			fmt.Printf("  Jobs interval:   %s\n", cfg.Ypanel.JobsInterval)
			fmt.Println()

			ready := cfg.Ypanel.Enabled && strings.TrimSpace(cfg.Ypanel.InstanceID) != "" &&
				strings.TrimSpace(cfg.Ypanel.EnrollToken) != "" && jErr == nil && jws != ""
			switch {
			case ready:
				fmt.Println("Readiness: READY — the agent reports on 'qpot up' (or run 'qpot ypanel test').")
			case !cfg.Ypanel.Enabled:
				fmt.Println("Readiness: DISABLED — run 'qpot ypanel setup' to enrol this host.")
			default:
				fmt.Println("Readiness: NOT READY — complete enrolment (see the fields marked 'no' above).")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

// boolMask renders a yes/no for status output without leaking secret values.
func boolMask(b bool) string {
	if b {
		return "set (yes)"
	}
	return "not set (no)"
}
