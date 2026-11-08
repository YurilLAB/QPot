// QPot - Safe, User-Friendly Honeypot Platform
// Main CLI entry point
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/intelligence"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// reValidName matches instance names: 1-32 chars, alphanumeric, hyphens, underscores.
var reValidName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)

// validateInstanceName returns an error if name contains characters that would
// break Docker container names, bridge names, or file system paths.
// instanceOptional are the commands that work without the instance named by
// -i existing: the ones that create it, and `honeypot list`, which shows the
// catalogue with default settings. Every other command requires it to exist.
var instanceOptional = map[string]bool{
	"qpot setup": true, "qpot up": true, "qpot cluster join": true, "qpot honeypot list": true, "qpot honeypot profiles": true,
}

// checkInstanceFlag validates the -i/--instance value of every command. Only
// `instance create` used to apply the naming rules, so e.g. `honeypot enable
// -i "my pot"` created a config for a name compose cannot use (container names
// with spaces) and that `instance create` then refused as existing.
func checkInstanceFlag(cmd *cobra.Command, args []string) error {
	f := cmd.Flags().Lookup("instance")
	if f == nil {
		return nil
	}
	name := f.Value.String()
	if err := validateInstanceName(name); err != nil {
		return err
	}
	if instanceOptional[cmd.CommandPath()] {
		return nil
	}
	if _, err := os.Stat(config.Default(name).ConfigPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("instance %q does not exist (create it with: qpot setup -i %s)", name, name)
	}
	return nil
}

func validateInstanceName(name string) error {
	if !reValidName.MatchString(name) {
		return fmt.Errorf("invalid instance name %q: must be 1-32 characters, start with alphanumeric, and contain only letters, digits, hyphens, or underscores", name)
	}
	return nil
}

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// On Windows, only os.Interrupt is reliably delivered; SIGTERM is defined
	// in syscall but never raised by the OS. Listening for both keeps the
	// behaviour identical on Linux/macOS while still working on Windows.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// cobra has already printed "Error: ..." to stderr.
	if err := run(ctx); err != nil {
		os.Exit(commandExitStatus(err))
	}
}

func commandExitStatus(err error) int {
	var coded *hostsetup.Error
	if errors.As(err, &coded) && strings.HasPrefix(coded.Code, "QP-CLUSTER-") {
		return hostsetup.ExitStatus(coded.Code)
	}
	return 1 // Preserve existing exit behavior for unrelated commands.
}

func run(ctx context.Context) error {
	rootCmd := &cobra.Command{
		Use:   "qpot",
		Short: "QPot - Safe honeypot platform for everyone",
		Long: `QPot is a user-friendly, security-first honeypot platform.
		
Run honeypots safely on your personal computer with complete isolation.
No security expertise required.

Each QPot instance has a unique ID (qp_*) for tracking and authentication.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, buildDate),
		// A failing command prints its error, not the whole usage text
		// (which buried the actual message); --help still shows usage.
		SilenceUsage:      true,
		PersistentPreRunE: checkInstanceFlag,
	}

	// Global flags
	var cfgFile string
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.qpot/config.yaml)")

	// Add commands
	rootCmd.AddCommand(newUpCommand())
	rootCmd.AddCommand(newDownCommand())
	rootCmd.AddCommand(newServeCommand())
	rootCmd.AddCommand(newSetupCommand())
	rootCmd.AddCommand(newDoctorCommand())
	rootCmd.AddCommand(newOverviewCommand())
	rootCmd.AddCommand(newGeoIPCommand())
	rootCmd.AddCommand(newStatusCommand())
	rootCmd.AddCommand(newInstanceCommand())
	rootCmd.AddCommand(newHoneypotCommand())
	rootCmd.AddCommand(newLogsCommand())
	rootCmd.AddCommand(newIDCommand())
	rootCmd.AddCommand(newClusterCommand())
	rootCmd.AddCommand(newDockerCommand())
	rootCmd.AddCommand(newConfigCommand())
	rootCmd.AddCommand(newDBCommand())
	rootCmd.AddCommand(newCanaryCommand())

	return rootCmd.ExecuteContext(ctx)
}

// backgroundServe starts the control plane in the background for `qpot up -d`
// (startBackgroundServe; tests stand it in).
var backgroundServe = startBackgroundServe

func newUpCommand() *cobra.Command {
	var (
		instanceName string
		detach       bool
	)

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start QPot instance",
		Long:  "Start a QPot instance with all configured honeypots",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			cfg, qpotID, err := loadInstance(instanceName)
			if err != nil {
				return err
			}

			// Pre-load ATT&CK data in background so it's ready when events arrive.
			if cfg.Intelligence.Enabled && cfg.Intelligence.FetchATTCK {
				go func() {
					loader := intelligence.NewATTCKLoader(cfg.Intelligence.ATTCKDataPath)
					loader.Load(context.Background())
				}()
			}

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}

			// Show QPot ID popup before starting
			showQPotIDPopup(qpotID.ID, cfg.InstanceName, cfg.WebUI.Port)

			// The containers always run detached; this process (or, with -d, a
			// background `qpot serve`) then runs the control plane. If they are
			// already up (e.g. docker restarted them after a reboot), just attach
			// the control plane instead of failing - that is what a systemd
			// service running `qpot up` needs.
			// An instance that is fully up already (containers + control plane)
			// is left alone: starting a second control plane fails on the web UI
			// port, and stopping afterwards would tear the running stack down.
			// "Fully" means every service it should run: after an unclean stop
			// docker brings back only the containers whose restart policy says
			// so, and attaching to those left the database and honeypots down.
			allUp, anyUp := mgr.AllRunning(ctx), mgr.IsRunning(ctx)
			servePID := runningServePID(cfg)
			if servePID != 0 && allUp {
				fmt.Printf("[OK] QPot instance '%s' is already running (control plane pid %d)\n", cfg.InstanceName, servePID)
				fmt.Printf("[INFO] Web UI: %s   Stop it with: qpot down -i %s\n", localBaseURL(cfg), cfg.InstanceName)
				return nil
			}
			startedContainers := false
			if allUp {
				fmt.Println("[INFO] Containers are already running; attaching the control plane")
			} else {
				if stopped, err := mgr.StoppedServices(ctx); err == nil && anyUp {
					fmt.Printf("[INFO] Starting the parts that are not running: %s\n", strings.Join(stopped, ", "))
				}
				// compose up -d starts what is missing and leaves the rest.
				if err := mgr.Start(ctx, true); err != nil {
					return fmt.Errorf("failed to start instance: %w", err)
				}
				startedContainers = !anyUp
			}
			if servePID != 0 {
				fmt.Printf("[OK] QPot instance '%s' is running (control plane pid %d)\n", cfg.InstanceName, servePID)
				fmt.Printf("[INFO] Web UI: %s   Stop it with: qpot down -i %s\n", localBaseURL(cfg), cfg.InstanceName)
				return nil
			}

			fmt.Printf("\n[OK] QPot instance '%s' started successfully\n", cfg.InstanceName)
			fmt.Printf("[INFO] QPot ID: %s\n", qpotID.ID)
			fmt.Printf("[INFO] Web UI: http://%s:%d\n", cfg.WebUI.BindAddr, cfg.WebUI.Port)
			fmt.Println("\nUse this QPot ID to track your honeypot activity in the Web UI")

			if detach {
				pid, logPath, err := backgroundServe(cfg)
				if err != nil {
					return fmt.Errorf("containers are up, but the control plane (web UI, intelligence) failed to start: %w", err)
				}
				fmt.Printf("[INFO] Control plane running in the background (pid %d)", pid)
				if logPath != "" {
					fmt.Printf(", log: %s", logPath)
				}
				fmt.Printf("\n[INFO] Stop everything with: qpot down -i %s\n", cfg.InstanceName)
				return nil
			}

			fmt.Println("\nPress Ctrl+C to stop")
			cpErr := runControlPlane(ctx, cfg, mgr)
			// Stop the containers when this run owned them, or when the control
			// plane ran and was asked to stop (Ctrl+C / systemd stop). A control
			// plane that failed to start must not take down containers that were
			// already running before this command.
			if startedContainers || cpErr == nil {
				if err := mgr.Stop(context.Background()); err != nil {
					return err
				}
			}
			return cpErr
		},
	}

	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().BoolVarP(&detach, "detach", "d", false, "run in background")

	return cmd
}

func newDownCommand() *cobra.Command {
	var instanceName string

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop QPot instance",
		Long:  "Stop a running QPot instance and all its honeypots",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}

			// Stop the background control plane first, so the HiFi recycler
			// does not try to recreate backends while they are torn down.
			stopBackgroundServe(cfg)

			if err := mgr.Stop(ctx); err != nil {
				return fmt.Errorf("failed to stop instance: %w", err)
			}

			fmt.Printf("[OK] QPot instance '%s' stopped\n", cfg.InstanceName)
			return nil
		},
	}

	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	return cmd
}

func newStatusCommand() *cobra.Command {
	var instanceName string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show QPot status",
		Long:  "Display status of all running honeypots and services",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Load QPot ID
			qpotID, _ := instance.LoadID(instanceName)
			if qpotID != nil {
				cfg.QPotID = qpotID.ID
			}

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}

			status, err := mgr.Status(ctx)
			if err != nil {
				return fmt.Errorf("failed to get status: %w", err)
			}

			fmt.Printf("Instance: %s\n", cfg.InstanceName)
			if cfg.QPotID != "" {
				fmt.Printf("QPot ID:  %s\n", cfg.QPotID)
			}
			fmt.Printf("Status:   %s\n", status.Overall)
			fmt.Printf("Database: %s\n", cfg.Database.Type)
			fmt.Println("\nHoneypots:")
			for _, hp := range status.Honeypots {
				statusIcon := "[OK]"
				if !hp.Running {
					statusIcon = "[--]"
				}
				fmt.Printf("  %s %-12s port %5d - %s\n", statusIcon, hp.Name, hp.Port, hp.Status)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	return cmd
}

func newInstanceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "instance",
		Short: "Manage QPot instances",
		Long:  "Create, list, and manage multiple QPot instances",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "create [name]",
		Short: "Create a new QPot instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]

			if err := validateInstanceName(name); err != nil {
				return err
			}

			// Refuse to clobber an existing instance. Re-running create would
			// otherwise overwrite its config and mint a NEW QPot ID, silently
			// wiping the enabled honeypots, cluster membership and
			// the identity used for attack tracking - a data-loss footgun.
			if _, statErr := os.Stat(config.Default(name).ConfigPath); statErr == nil {
				return fmt.Errorf("instance %q already exists; remove it first with 'qpot instance remove %s' or choose another name", name, name)
			}

			cfg, qpotID, err := createInstance(ctx, name)
			if err != nil {
				return err
			}

			fmt.Printf("[OK] Created QPot instance '%s'\n", name)
			fmt.Printf("     QPot ID: %s\n", qpotID.ID)
			fmt.Printf("     Data directory: %s\n", cfg.DataPath)
			fmt.Printf("     Config file: %s\n", cfg.ConfigPath)
			fmt.Println("\n[IMPORTANT] Save your QPot ID - you'll need it to access the Web UI!")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all QPot instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			instances, err := instance.List()
			if err != nil {
				return fmt.Errorf("failed to list instances: %w", err)
			}

			if len(instances) == 0 {
				fmt.Println("No QPot instances found")
				return nil
			}

			fmt.Println("QPot instances:")
			fmt.Println("Name      Status     QPot ID               Ports")
			fmt.Println("---------- ---------- --------------------- -------------")
			for _, inst := range instances {
				status := "stopped"
				if inst.Running {
					status = "running"
				}
				fmt.Printf("%-10s %-10s %-21s %s\n", inst.Name, status, inst.QPotID, inst.Ports)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a QPot instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]

			if err := instance.Remove(ctx, name); err != nil {
				return fmt.Errorf("failed to remove instance: %w", err)
			}

			fmt.Printf("[OK] Removed QPot instance '%s'\n", name)
			return nil
		},
	})

	return cmd
}

// honeypotCommandError attaches the same stable failure code the web API
// returns. The existing CLI exit status remains unchanged; callers can explain
// the code with qpot doctor --explain without losing the underlying cause.
func honeypotCommandError(name string, err error, saved bool) error {
	if err == nil {
		return nil
	}
	code := ""
	switch {
	case saved:
		code = "QP-INST-008"
	case errors.Is(err, instance.ErrUnknownHoneypot):
		code = "QP-INPUT-003"
	case errors.Is(err, instance.ErrNoSettings), errors.Is(err, instance.ErrInvalidSetting), errors.Is(err, instance.ErrNeedsSettings):
		code = "QP-INPUT-012"
	case errors.Is(err, instance.ErrSaveFailed):
		code = "QP-INST-002"
	default:
		return err
	}
	coded := hostsetup.E(code).WithWhy("%s", termSafe(err.Error())).Wrap(err)
	if code == "QP-INPUT-012" {
		coded.WithFix("See accepted values with qpot honeypot set --help. Explore industrial devices with qpot honeypot profiles conpot.")
	}
	if saved {
		coded.WithFix("The configuration was saved. Check the honeypot status and logs before retrying, or start the instance with qpot up -d.")
		if name == "refrigeration" {
			coded.WithFix("The configuration was saved. Check QPot service output for local image-build or startup errors, and refrigeration logs if a container exists. The first build needs Docker access to the builder image; the saved scenario may not be live.")
		}
	}
	return fmt.Errorf("%w: %s Fix: %s", coded, coded.Cause(), coded.Remedy())
}

func newHoneypotCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "honeypot",
		Short: "Manage honeypots",
		Long:  "Enable, disable, and configure individual honeypots",
	}

	var instanceName string

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List available honeypots",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Source the actual config so ports/risk/enabled reflect this
			// instance (falls back to defaults for an uncreated instance).
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			names := make([]string, 0, len(cfg.Honeypots))
			for n := range cfg.Honeypots {
				names = append(names, n)
			}
			sort.Strings(names)

			fmt.Printf("Available honeypots (instance %q):\n", instanceName)
			ports := instance.HostPortMappings(cfg)
			fmt.Println("Name             Host ports                 Risk     On  Description")
			fmt.Println("---------------- -------------------------- -------- --- -------------------------------------------")
			for _, n := range names {
				hp := cfg.Honeypots[n]
				on := " "
				if hp.Enabled {
					on = "x"
				}
				var published []string
				for _, m := range ports[n] {
					published = append(published, fmt.Sprintf("%d/%s", m.HostPort, m.Protocol))
				}
				portText := strings.Join(published, ", ")
				if portText == "" {
					portText = "—"
				}
				fmt.Printf("%-16s %-26s %-8s [%s] %s\n", n, portText, hp.RiskLevel, on, instance.HoneypotDescription(n))
			}
			fmt.Printf("\n%d honeypots supported. Enable one with: qpot honeypot enable <name>\n", len(names))
			fmt.Println("Host ports are configured mappings, not a live reachability check. Industrial devices: qpot honeypot profiles conpot")
			return nil
		},
	}
	listCmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	enableCmd := &cobra.Command{
		Use:   "enable [honeypot]",
		Short: "Enable a honeypot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			hpName := args[0]

			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// The web API's POST /api/honeypots makes the same change
			// (instance.SetHoneypotEnabled): unknown names and LLM honeypots
			// without a provider are refused, and a running instance
			// starts the honeypot.
			res, err := instance.SaveHoneypotEnabled(cfg, hpName, true)
			if err != nil {
				return honeypotCommandError(hpName, err, false)
			}
			fmt.Printf("[OK] Enabled honeypot '%s' for instance '%s'\n", hpName, instanceName)
			fmt.Println("     Run 'qpot up' to apply changes")
			if err := instance.ApplyHoneypotEnabled(ctx, cfg, res, nil); err != nil {
				return honeypotCommandError(hpName, err, true)
			}
			if res.Applied {
				fmt.Printf("[OK] Started honeypot '%s'\n", hpName)
			}
			return nil
		},
	}
	enableCmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	disableCmd := &cobra.Command{
		Use:   "disable [honeypot]",
		Short: "Disable a honeypot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			hpName := args[0]

			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Unknown names are refused (a typo once reported "Disabled"),
			// and a running instance stops the honeypot.
			res, err := instance.SaveHoneypotEnabled(cfg, hpName, false)
			if err != nil {
				return honeypotCommandError(hpName, err, false)
			}
			fmt.Printf("[OK] Disabled honeypot '%s' for instance '%s'\n", hpName, instanceName)
			if err := instance.ApplyHoneypotEnabled(ctx, cfg, res, nil); err != nil {
				return honeypotCommandError(hpName, err, true)
			}
			if res.Applied {
				fmt.Printf("[OK] Stopped honeypot '%s'\n", hpName)
			}
			return nil
		},
	}
	disableCmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	setCmd := &cobra.Command{
		Use:   "set [honeypot] key=value...",
		Short: "Set honeypot settings (e.g. the LLM provider of beelzebub/galah)",
		Long: `Set per-honeypot settings stored in the instance config (custom_config).

The LLM-backed honeypots need a provider before they can be enabled:

  qpot honeypot set galah llm_provider=ollama llm_server_url=http://10.0.0.5:11434 llm_model=llama3.1
  qpot honeypot set beelzebub llm_provider=ollama llm_model=llama3.1 llm_host=http://10.0.0.5:11434/api/chat

Cowrie presents one of the Cowrie image's personas, picked per instance. Pin
one, or set how many days (0-365, default 365) it keeps the identity it drew:

  qpot honeypot set cowrie persona=debian-bookworm
  qpot honeypot set cowrie persona_rotation=30

On the server personas Cowrie also carries an ops box's files (SSH key, shell
history, backup script, cloud credentials, a database dump) whose secrets are
canaries (doc/canary.md). Turn them off:

  qpot honeypot set cowrie bait=off

For a Linux industrial support host, select archived maintenance inventories,
communication exports and planted credentials instead of generic ops files:

  qpot honeypot set cowrie persona=debian-bookworm bait_profile=industrial

The files reference the selected Conpot device as a separate archived asset;
they do not turn Cowrie into a PLC or install an engineering runtime. Reapply
bait_profile=industrial to refresh them after changing the device reference.
Use bait_target=refrigeration to reference the separate cold storage supervisor:

  qpot honeypot set cowrie bait_profile=industrial bait_target=refrigeration

Empty bait_profile= restores ops files. Reading files alone does not trip a
canary: a watched value must be observed in captured activity. Previously
planted values remain watched across role changes or failed recreations.

Conpot emulates one of the Conpot image's devices, also picked per instance,
and publishes only that device's ports. Pin one (IEC104, guardian_ast, ipmi,
kamstrup_382, beckhoff_cx, building_automation, hart_gateway, iccp,
plc_modbus):

  qpot honeypot set conpot template=plc_modbus

The refrigeration service presents a legacy cold storage supervisor with a
documented XML management subset and simulated equipment. Its site scenarios
keep separate settings and histories:

  qpot honeypot set refrigeration site_profile=plasma
  qpot honeypot enable refrigeration

Empty site_profile= restores retail. First start builds its image locally from
bundled source; Docker needs access to the builder image. It never controls real
refrigeration equipment.

An empty value (key=) removes a setting. If the honeypot is enabled and the
instance is running, it is recreated with the new settings.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hpName := args[0]
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			// Shared with PUT /api/honeypots/settings.
			res, err := instance.ApplySettings(cmd.Context(), cfg, hpName, instance.ParseSettingArgs(args[1:]), nil)
			if res != nil && res.Saved {
				fmt.Printf("[OK] Updated %s settings for instance '%s'\n", hpName, instanceName)
			}
			if err != nil {
				return honeypotCommandError(hpName, err, res != nil && res.Saved)
			}
			if len(res.Missing) > 0 {
				fmt.Printf("     %s still needs: %s\n", hpName, strings.Join(res.Missing, ", "))
			}
			if res.Recreated {
				fmt.Printf("[OK] %s recreated with the new settings\n", hpName)
			}
			return nil
		},
	}
	setCmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	profilesCmd := &cobra.Command{
		Use:   "profiles [honeypot]",
		Short: "Explore industrial devices, protocols and ports (Conpot)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && args[0] != "conpot" {
				return fmt.Errorf("device profiles are available for conpot; use: qpot honeypot profiles conpot")
			}
			cfg, err := config.Load(instanceName)
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Industrial control systems and related devices (instance %q)\n", instanceName)
			if err != nil {
				// Keep recovery possible without pretending the broken instance has defaults.
				fmt.Fprintf(out, "Effective device unavailable: %v\nCatalog only; no settings were changed.\n\n", err)
			} else {
				selected := instance.ConpotProfile(cfg)
				hp, _ := cfg.GetHoneypotConfig("conpot")
				mode := "automatic choice"
				if hp.CustomConfig["template"] != "" {
					mode = "explicit template"
				}
				fmt.Fprintf(out, "Effective device: %s · %s [%s] (%s)\n\n", selected.Label, selected.Model, selected.ID, mode)
			}
			for _, p := range instance.ConpotProfiles() {
				fmt.Fprintf(out, "%s — %s [%s]\n  Model: %s\n  %s\n  Protocols: %s\n", p.ID, p.Label, p.Category, p.Model, p.Description, strings.Join(p.Protocols, ", "))
				var ports []string
				for _, n := range p.TCP {
					ports = append(ports, fmt.Sprintf("%d/tcp", n))
				}
				for _, n := range p.UDP {
					ports = append(ports, fmt.Sprintf("%d/udp", n))
				}
				fmt.Fprintf(out, "  Device ports (container): %s\n  Limits: %s\n\n", strings.Join(ports, ", "), p.Limitations)
			}
			fmt.Fprintln(out, "Select: qpot honeypot set conpot template=<id> -i "+instanceName)
			fmt.Fprintln(out, "Enable separately: qpot honeypot enable conpot -i "+instanceName)
			fmt.Fprintln(out, "Host ports may differ; qpot honeypot list shows configured mappings, not live reachability.")
			return nil
		},
	}
	profilesCmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	cmd.AddCommand(listCmd, profilesCmd, enableCmd, disableCmd, setCmd)

	return cmd
}

func newLogsCommand() *cobra.Command {
	var (
		instanceName string
		follow       bool
		tail         int
	)

	cmd := &cobra.Command{
		Use:   "logs [honeypot]",
		Short: "View honeypot logs",
		Long:  "View logs from a specific honeypot or all honeypots",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			var hpName string
			if len(args) > 0 {
				hpName = args[0]
			}

			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}

			logs, err := mgr.GetLogs(ctx, hpName, follow, tail)
			if err != nil {
				return fmt.Errorf("failed to get logs: %w", err)
			}

			for line := range logs {
				fmt.Println(termSafe(line)) // honeypot logs carry attacker input
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow log output")
	cmd.Flags().IntVarP(&tail, "tail", "n", 100, "number of lines to show from end")

	return cmd
}

func newIDCommand() *cobra.Command {
	var instanceName string

	cmd := &cobra.Command{
		Use:   "id",
		Short: "Show QPot ID",
		Long:  "Display the QPot ID for an instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			qpotID, err := instance.LoadID(instanceName)
			if err != nil {
				return fmt.Errorf("no QPot ID found for instance '%s': %w", instanceName, err)
			}

			fmt.Printf("Instance: %s\n", instanceName)
			fmt.Printf("QPot ID:  %s\n", qpotID.ID)
			fmt.Println("\nUse this ID to access the Web UI and track your honeypot")
			return nil
		},
	}

	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	return cmd
}

// popupCmd is one desktop notification helper to launch.
type popupCmd struct {
	name  string
	args  []string
	env   []string // added to the environment
	delay time.Duration
}

// popupIDEnv hands the QPot ID to the notification scripts. Any local user
// can read another process's command line (ps, /proc/<pid>/cmdline), so the
// ID never goes into an argument; a process's environment is readable only
// by its own user.
const popupIDEnv = "QPOT_POPUP_ID"

// popupCommands returns the notification helpers to run on goos. has reports
// whether a binary is on PATH.
func popupCommands(goos, id, instanceName string, webPort int, has func(string) bool) []popupCmd {
	env := []string{popupIDEnv + "=" + id}
	switch goos {
	case "windows":
		// Prefer pwsh (PowerShell 7+, the default on modern installs); fall
		// back to legacy Windows PowerShell if it isn't on PATH.
		shell := "powershell"
		if has("pwsh") {
			shell = "pwsh"
		}
		text := fmt.Sprintf("\"QPot ID: $env:%s`nWeb UI: http://localhost:%d\"", popupIDEnv, webPort)
		balloon := "Add-Type -AssemblyName System.Windows.Forms\n" +
			"$notify = New-Object System.Windows.Forms.NotifyIcon\n" +
			"$notify.Icon = [System.Drawing.SystemIcons]::Information\n" +
			"$notify.Visible = $true\n" +
			"$notify.BalloonTipTitle = \"QPot Started\"\n" +
			"$notify.BalloonTipText = " + text + "\n" +
			"$notify.ShowBalloonTip(10000)\n"
		box := "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show(" +
			text + ", \"QPot Started\", \"OK\", \"Information\")"
		return []popupCmd{
			{name: shell, args: []string{"-NoProfile", "-Command", balloon}, env: env},
			{name: shell, args: []string{"-NoProfile", "-Command", box}, env: env, delay: 500 * time.Millisecond},
		}

	case "darwin":
		idExpr := `(system attribute "` + popupIDEnv + `")`
		notify := fmt.Sprintf(`display notification ("QPot ID: " & %s) with title "QPot Started" subtitle "Web UI: http://localhost:%d"`, idExpr, webPort)
		alert := fmt.Sprintf(`display alert "QPot Started" message ("QPot ID: " & %s & return & return & "Web UI: http://localhost:%d" & return & return & "Save this ID to access your honeypot!") as informational buttons {"Copy ID", "OK"} default button "OK"`, idExpr, webPort)
		return []popupCmd{
			{name: "osascript", args: []string{"-e", notify}, env: env},
			{name: "osascript", args: []string{"-e", alert}, env: env, delay: 500 * time.Millisecond},
		}

	default:
		// Linux: try notify-send, then zenity, then kdialog. Headless or
		// minimal installs (common on Arch) may have none of these — that's
		// fine, the console box still shows the ID. These tools only take
		// the text as an argument, so the popup names the command that shows
		// the ID instead of the ID itself.
		hint := fmt.Sprintf("Show your QPot ID with: qpot id -i %s", instanceName)
		web := fmt.Sprintf("Web UI: http://localhost:%d", webPort)
		switch {
		case has("notify-send"):
			return []popupCmd{{name: "notify-send", args: []string{"-t", "10000", "QPot Started", hint + "\n\n" + web}}}
		case has("zenity"):
			return []popupCmd{{name: "zenity", args: []string{"--info", "--title=QPot Started", "--width=400",
				"--text=<big><b>QPot started</b></big>\n\n" + hint + "\n\n" + web}}}
		case has("kdialog"):
			return []popupCmd{{name: "kdialog", args: []string{"--title", "QPot Started", "--msgbox", hint + "\n" + web}}}
		}
	}
	return nil
}

// showQPotIDPopup displays a GUI notification with the QPot ID
func showQPotIDPopup(id, instanceName string, webPort int) {
	// The popup is best-effort: console output (printed unconditionally
	// below) is the source of truth.
	tryStart := func(p popupCmd) {
		c := exec.Command(p.name, p.args...)
		c.Env = append(os.Environ(), p.env...)
		if err := c.Start(); err != nil {
			slog.Debug("popup helper failed", "tool", p.name, "error", err)
			return
		}
		// Reap the child so it doesn't linger as a zombie on Linux/macOS
		// once the user dismisses the dialog.
		go func() { _ = c.Wait() }()
	}
	for _, p := range popupCommands(runtime.GOOS, id, instanceName, webPort, hasBinary) {
		if p.delay == 0 {
			tryStart(p)
			continue
		}
		go func(p popupCmd) {
			time.Sleep(p.delay)
			tryStart(p)
		}(p)
	}

	// Also print to console
	fmt.Println("╔════════════════════════════════════════════════════════╗")
	fmt.Println("║                    QPot Started                        ║")
	fmt.Println("╠════════════════════════════════════════════════════════╣")
	fmt.Printf("║  QPot ID: %-45s║\n", id)
	fmt.Printf("║  Web UI:  http://localhost:%-28d║\n", webPort)
	fmt.Println("║                                                        ║")
	fmt.Println("║  Save this ID - you'll need it to access the Web UI   ║")
	fmt.Println("╚════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// newClusterCommand creates the cluster management command
func newClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cluster",
		Aliases: []string{"group", "pair", "networking"},
		Short:   "Pair honeypots into a group and manage them together",
		Long: `Pair multiple QPot honeypot nodes into a managed group (cluster).

A group lets you manage many honeypot deployments together: members gossip
their health and attack stats, and the Pairing/Networking tab in the web UI
shows every node's online status, uptime, and total requests.

Aliases: 'qpot group ...' and 'qpot pair ...' work the same as 'qpot cluster'.

Typical flow:
  qpot cluster init   --name mygroup    # create a group (prints the group ID + password)
  qpot cluster join   --id <group-id>   # pair another node into the group
  qpot cluster status                   # show the group summary
  qpot cluster nodes                    # list paired honeypots
  qpot cluster leave                    # unpair this node
  qpot cluster remove <node-id>         # on the enrollment host: remove another node`,
	}

	cmd.AddCommand(newClusterInitCommand())
	cmd.AddCommand(newClusterJoinCommand())
	cmd.AddCommand(newClusterUpgradeCommand())
	cmd.AddCommand(newClusterStatusCommand())
	cmd.AddCommand(newClusterLeaveCommand())
	cmd.AddCommand(newClusterNodesCommand())
	cmd.AddCommand(newClusterRequestsCommand())
	cmd.AddCommand(newClusterApproveCommand())
	cmd.AddCommand(newClusterDenyCommand())
	cmd.AddCommand(newClusterRemoveCommand())

	return cmd
}

func newClusterInitCommand() *cobra.Command {
	var (
		clusterName string
		password    string
		bindAddr    string
		bindPort    int
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new cluster",
		Long:  "Create a new QPot cluster with password protection",
		Example: `  qpot cluster init --name production --password "SecurePass123!"
  qpot cluster init --name east-coast --password "MyP@ssw0rd" --bind-addr 192.168.1.10 --bind-port 7946`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get home directory
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}

			dataPath := filepath.Join(homeDir, ".qpot", "cluster")
			mgr := cluster.NewManager(dataPath)

			// Check if already in a cluster
			existing, _ := mgr.LoadCluster()
			if existing != nil {
				return fmt.Errorf("already in cluster %s (%s). Leave first with 'qpot cluster leave'", existing.Name, existing.ID)
			}

			// Prompt for password if not provided (no echo)
			if password == "" {
				fmt.Print("Enter cluster password (min 8 chars): ")
				pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println() // newline after hidden input
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				password = string(pwBytes)
			}

			if len(password) < 8 {
				return fmt.Errorf("password must be at least 8 characters")
			}

			// Create cluster config
			cfg := cluster.DefaultClusterConfig()
			if bindAddr != "" {
				cfg.BindAddr = bindAddr
			}
			// Members gossip to the address the host advertises; a wildcard
			// bind address is not one they can reach.
			cfg.AdvertiseAddr = cfg.BindAddr
			if ip := net.ParseIP(strings.Trim(cfg.BindAddr, "[]")); cfg.BindAddr == "" || (ip != nil && ip.IsUnspecified()) {
				cfg.AdvertiseAddr = getLocalIP()
			}
			if bindPort != 0 {
				cfg.BindPort = bindPort
			}

			// Initialize cluster
			c, err := mgr.InitCluster(clusterName, password, cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize cluster: %w", err)
			}

			// Start cluster manager
			// The cluster runs inside the long-lived QPot control plane, not in
			// this short-lived command (which used to Start it and exit at once).
			if err := mgr.SaveSecret(); err != nil {
				return fmt.Errorf("failed to store cluster secret: %w", err)
			}

			fmt.Printf("\n[OK] Cluster initialized successfully\n")
			fmt.Printf("     Cluster ID:   %s\n", c.ID)
			fmt.Printf("     Cluster Name: %s\n", c.Name)
			fmt.Printf("     Node ID:      %s\n", c.LocalNode.ID)
			fmt.Printf("     Bind Address: %s\n", net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindPort)))
			fmt.Println("\n[IMPORTANT] Save your Cluster ID and Password!")
			fmt.Println("            Other nodes will need both to join.")
			fmt.Printf("\nTo join this cluster, run:\n")
			fmt.Printf("  qpot cluster join --id %s --seed %s\n", c.ID, net.JoinHostPort(cfg.AdvertiseAddr, strconv.Itoa(cfg.BindPort)))
			fmt.Println("\nThe cluster runs with the QPot control plane: start it with 'qpot up' (or")
			fmt.Println("restart a running 'qpot up -d' / 'qpot serve') so other nodes can join.")

			return nil
		},
	}

	cmd.Flags().StringVarP(&clusterName, "name", "n", "", "Cluster name (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Cluster password (min 8 chars)")
	cmd.Flags().StringVar(&bindAddr, "bind-addr", "0.0.0.0", "Bind address for cluster communication")
	cmd.Flags().IntVar(&bindPort, "bind-port", cluster.DefaultClusterPort, "Bind port for cluster communication")
	if err := cmd.MarkFlagRequired("name"); err != nil {
		// Marking a known flag as required can only fail when the flag does
		// not exist, which is a programmer error here.
		panic(fmt.Errorf("cluster init: mark --name required: %w", err))
	}

	return cmd
}

func newClusterJoinCommand() *cobra.Command {
	var (
		clusterID    string
		password     string
		seedNodes    []string
		nodeName     string
		nodeAddr     string
		nodePort     int
		qpotID       string
		instanceName string
		operatorCert bool
		caFile       string
	)

	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join an existing cluster",
		Long:  "Join a QPot cluster using the cluster ID, password, and seed node address",
		Example: `  qpot cluster join --id qc_abc123 --password "SecurePass123!" --seed 192.168.1.10:7946
  qpot cluster join --id qc_abc123 -p "MyP@ssw0rd" -s 10.0.0.5:7946 -s 10.0.0.6:7946 --node-name sensor-01`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get home directory
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}

			dataPath := filepath.Join(homeDir, ".qpot", "cluster")
			mgr := cluster.NewManager(dataPath)

			// Check if already in a cluster
			existing, _ := mgr.LoadCluster()
			if existing != nil {
				return fmt.Errorf("already in cluster %s. Leave first with 'qpot cluster leave'", existing.ID)
			}
			// A missing CA bundle is reported before the password is asked for.
			if caFile != "" {
				if _, err := os.Stat(caFile); err != nil {
					return fmt.Errorf("--ca-file: %w", err)
				}
			}

			// Prompt for password if not provided (no echo)
			if password == "" {
				fmt.Print("Enter cluster password: ")
				pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println() // newline after hidden input
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				password = string(pwBytes)
			}

			if instanceName == "" {
				instanceName = "default"
			}

			// Auto-detect node address if not provided
			if nodeAddr == "" {
				// Try to get local IP
				nodeAddr = getLocalIP()
			}

			if nodeName == "" {
				hostname, _ := os.Hostname()
				nodeName = hostname
			}

			// Create local node
			localNode := &cluster.Node{
				Name:         nodeName,
				Address:      nodeAddr,
				Port:         nodePort,
				InstanceName: instanceName,
				Metadata:     make(map[string]string),
				Capabilities: []string{"honeypot", "sensor"},
			}

			// Join cluster: by default the seed must prove itself with the
			// cluster CA the cluster ID names; an operator certificate is
			// accepted only when asked for.
			c, err := mgr.JoinClusterTrusting(clusterID, password, localNode, seedNodes,
				cluster.JoinTrust{OperatorCerts: operatorCert, CAFile: caFile})
			if err != nil {
				return fmt.Errorf("failed to join cluster: %w", err)
			}

			// The cluster runs inside the long-lived QPot control plane.
			if err := mgr.SaveSecret(); err != nil {
				return fmt.Errorf("failed to store cluster secret: %w", err)
			}

			fmt.Printf("\n[OK] Successfully joined cluster\n")
			fmt.Printf("     Cluster ID:   %s\n", c.ID)
			fmt.Printf("     Cluster Name: %s\n", c.Name)
			fmt.Printf("     Node ID:      %s\n", c.LocalNode.ID)
			fmt.Printf("     Total Nodes:  %d\n", len(c.Nodes))
			fmt.Println("\nMembership is kept up by the QPot control plane: run 'qpot up' (or restart")
			fmt.Println("'qpot up -d' / 'qpot serve') on this node.")

			return nil
		},
	}

	cmd.Flags().StringVarP(&clusterID, "id", "i", "", "Cluster ID (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Cluster password")
	cmd.Flags().StringArrayVarP(&seedNodes, "seed", "s", nil, "Seed node addresses (format: host:port)")
	cmd.Flags().StringVar(&nodeName, "node-name", "", "Name for this node (default: hostname)")
	cmd.Flags().StringVar(&nodeAddr, "node-addr", "", "Address for this node (auto-detected if not set)")
	cmd.Flags().IntVar(&nodePort, "node-port", cluster.DefaultClusterPort, "Port for cluster communication")
	// The QPot ID is the instance's web API credential: it is no longer sent
	// to the cluster, and the flag is accepted so older scripts still run.
	cmd.Flags().StringVar(&qpotID, "qpot-id", "", "unused")
	if err := cmd.Flags().MarkDeprecated("qpot-id", "the QPot ID is no longer sent to the cluster"); err != nil {
		panic(fmt.Errorf("cluster join: deprecate --qpot-id: %w", err))
	}
	cmd.Flags().StringVar(&instanceName, "instance", "default", "QPot instance name")
	cmd.Flags().BoolVar(&operatorCert, "operator-cert", false,
		"Also accept a seed serving a certificate from your own or a public CA (tls_cert_path in its cluster.json), checked against the system roots")
	cmd.Flags().StringVar(&caFile, "ca-file", "",
		"PEM bundle the seed's operator certificate is checked against instead of the system roots (implies --operator-cert)")
	if err := cmd.MarkFlagRequired("id"); err != nil {
		panic(fmt.Errorf("cluster join: mark --id required: %w", err))
	}
	if err := cmd.MarkFlagRequired("seed"); err != nil {
		panic(fmt.Errorf("cluster join: mark --seed required: %w", err))
	}

	return cmd
}

func newClusterUpgradeCommand() *cobra.Command {
	var password string
	var yes bool
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Safely upgrade a stopped legacy cluster and require members to rejoin",
		Long:  "Preserve the saved cluster settings and local instance, back up the old membership, and atomically rotate cluster trust. Stop all old control planes and update every node first. Run this only on the chosen enrollment host; other nodes must leave and rejoin using the new cluster ID. Honeypot/event data is not changed or backed up by this command.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			defer func() {
				var coded *hostsetup.Error
				if errors.As(resultErr, &coded) {
					resultErr = fmt.Errorf("%w: %s Fix: %s", resultErr, coded.Cause(), coded.Remedy())
				}
			}()
			dir, err := cluster.DefaultDataPath()
			if err != nil {
				return hostsetup.E("QP-CLUSTER-006").WithWhy("Cannot locate the saved cluster directory.").Wrap(err)
			}
			mgr := cluster.NewManager(dir)
			c, err := mgr.LoadCluster()
			if err != nil {
				return hostsetup.E("QP-CLUSTER-006").WithWhy("Cannot read a valid saved cluster configuration; restore or repair it before upgrading.").Wrap(err)
			}
			if c == nil {
				return hostsetup.E("QP-CLUSTER-006").WithWhy("No saved cluster is available to upgrade.")
			}
			if password == "" {
				err = mgr.UnlockFromSecret()
			} else {
				err = mgr.UnlockPassword(password)
			}
			if err != nil {
				return hostsetup.E("QP-CLUSTER-006").WithWhy("Cannot unlock the cluster for upgrade; supply the correct password or stored secret.").Wrap(err)
			}
			if !yes {
				cmd.Printf("Upgrade cluster %q? Its ID and signing credentials will change; every member must update and rejoin. Settings/local instance and a private config backup will be kept. [y/N]: ", c.Name)
				var answer string
				if _, err := fmt.Fscanln(cmd.InOrStdin(), &answer); err != nil || (answer != "y" && answer != "Y") {
					cmd.Println("Aborted; cluster unchanged")
					return nil
				}
			}
			upgraded, backup, err := mgr.UpgradeCluster()
			if err != nil {
				if backup != "" {
					cmd.Printf("Original cluster configuration backup: %s\n", backup)
				}
				return err
			}
			cmd.Printf("Cluster upgraded to protocol %d. New cluster ID: %s\n", upgraded.Version, upgraded.ID)
			cmd.Printf("Original configuration/membership backup: %s (contains old secrets; keep private).\n", backup)
			cmd.Println("Local instance settings and event stores were not changed. Start the enrollment host's control plane, then have each updated member leave its old cluster and rejoin using the new ID. The saved approval setting still applies.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "Cluster password (defaults to stored secret or QPOT_CLUSTER_PASSWORD)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm trust rotation and member re-enrollment")
	return cmd
}

func newClusterStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show cluster status",
		Long:  "Display status information about the current cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}

			dataPath := filepath.Join(homeDir, ".qpot", "cluster")
			mgr := cluster.NewManager(dataPath)

			c, err := mgr.LoadCluster()
			if err != nil {
				return fmt.Errorf("failed to load cluster: %w", err)
			}
			if c == nil {
				fmt.Println("Not a member of any cluster")
				fmt.Println("\nTo create a cluster:")
				fmt.Println("  qpot cluster init --name <name>")
				fmt.Println("\nTo join a cluster:")
				fmt.Println("  qpot cluster join --id <cluster-id> --seed <host:port>")
				return nil
			}

			status := mgr.GetStatus()
			if status == nil {
				return fmt.Errorf("failed to get cluster status")
			}

			fmt.Println("Cluster Status")
			fmt.Println("==============")
			fmt.Printf("Cluster ID:    %s\n", status.ID)
			fmt.Printf("Cluster Name:  %s\n", status.Name)
			fmt.Printf("Protocol:      %d\n", c.Version)
			fmt.Printf("Status:        %s\n", map[bool]string{true: "running", false: "stopped"}[status.IsRunning])
			switch {
			case c.Version > cluster.ProtocolVersion:
				fmt.Println("\n[!] This cluster uses a newer, unsupported protocol")
				fmt.Println("    and does not start. Update QPot to support this protocol; do not downgrade")
				fmt.Println("    its trust state or run a legacy cluster upgrade.")
			case c.Version < cluster.ProtocolVersion:
				fmt.Println("\n[!] This cluster uses legacy shared signing credentials")
				fmt.Println("    and does not start. Stop old control planes, update all nodes, then run")
				fmt.Println("    'qpot cluster upgrade' on the enrollment host; other nodes must rejoin.")
			case c.NodeCertificate == "" || c.NodeKey == "" || c.MemberKey == "":
				fmt.Println("\n[!] This cluster's node certificate, private key or membership credential is missing")
				fmt.Println("    and does not start. Restore trusted current-protocol state or re-enroll")
				fmt.Println("    through the enrollment host. A legacy upgrade cannot repair this identity.")
			}
			fmt.Printf("\nNodes:\n")
			fmt.Printf("  Total:       %d\n", status.NodeCount)
			fmt.Printf("  Healthy:     %d\n", status.HealthyNodes)
			if status.SuspectNodes > 0 {
				fmt.Printf("  Suspect:     %d\n", status.SuspectNodes)
			}
			if status.FailedNodes > 0 {
				fmt.Printf("  Failed:      %d\n", status.FailedNodes)
			}
			fmt.Printf("\nEvents:        %d total\n", status.TotalEvents)

			// Show local node info
			if c.LocalNode != nil {
				fmt.Printf("\nLocal Node:\n")
				fmt.Printf("  Node ID:     %s\n", c.LocalNode.ID)
				fmt.Printf("  Name:        %s\n", c.LocalNode.Name)
				fmt.Printf("  Address:     %s:%d\n", c.LocalNode.Address, c.LocalNode.Port)
				fmt.Printf("  Status:      %s\n", c.LocalNode.Status)
			}

			return nil
		},
	}

	return cmd
}

func newClusterLeaveCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "leave",
		Short: "Leave the cluster",
		Long:  "Remove this node from the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}

			dataPath := filepath.Join(homeDir, ".qpot", "cluster")
			mgr := cluster.NewManager(dataPath)

			c, err := mgr.LoadCluster()
			if err != nil {
				return fmt.Errorf("failed to load cluster: %w", err)
			}
			if c == nil {
				fmt.Println("Not a member of any cluster")
				return nil
			}

			if !force {
				fmt.Printf("Are you sure you want to leave cluster '%s' (%s)? [y/N]: ", c.Name, c.ID)
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					fmt.Println("Aborted")
					return nil
				}
			}

			// Stop cluster manager
			if err := mgr.Stop(); err != nil {
				slog.Warn("Failed to stop cluster manager", "error", err)
			}

			// Leave cluster
			if err := mgr.LeaveCluster(); err != nil {
				return fmt.Errorf("failed to leave cluster: %w", err)
			}

			fmt.Println("[OK] Left cluster successfully")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func newClusterNodesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "List cluster nodes",
		Long:  "Display information about all nodes in the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}

			dataPath := filepath.Join(homeDir, ".qpot", "cluster")
			mgr := cluster.NewManager(dataPath)

			c, err := mgr.LoadCluster()
			if err != nil {
				return fmt.Errorf("failed to load cluster: %w", err)
			}
			if c == nil {
				fmt.Println("Not a member of any cluster")
				return nil
			}

			nodes := mgr.GetNodes()
			if len(nodes) == 0 {
				fmt.Println("No nodes in cluster")
				return nil
			}

			fmt.Println("Cluster Nodes")
			fmt.Println("=============")
			fmt.Printf("%-12s %-15s %-20s %-10s %-12s\n", "NODE ID", "NAME", "ADDRESS", "STATUS", "EVENTS")
			fmt.Println(strings.Repeat("-", 80))

			for _, node := range nodes {
				nodeID := node.ID
				if len(nodeID) > 12 {
					nodeID = nodeID[:12]
				}
				fmt.Printf("%-12s %-15s %-20s %-10s %-12d\n",
					nodeID,
					truncate(termSafe(node.Name), 15),
					termSafe(fmt.Sprintf("%s:%d", node.Address, node.Port)),
					node.Status,
					node.Stats.TotalEvents)
			}

			return nil
		},
	}

	return cmd
}

// localClusterManager loads this node's cluster (as host) for the approval
// commands. They talk to the running control plane over the cluster API,
// because pending join requests live in that process's memory.
func localClusterManager() (*cluster.Manager, *cluster.Cluster, error) {
	dir, err := cluster.DefaultDataPath()
	if err != nil {
		return nil, nil, err
	}
	mgr := cluster.NewManager(dir)
	c, err := mgr.LoadCluster()
	if err != nil || c == nil {
		return nil, nil, fmt.Errorf("this node is not a cluster host (run 'qpot cluster init' first)")
	}
	return mgr, c, nil
}

// clusterAPIRequest performs an authenticated request to the local cluster API
// and returns the response body. Used by the host-side approval commands. The
// connection is verified like any cluster peer (automatic cluster CA or the
// operator's certificate).
func clusterAPIRequest(method, path, password string, body []byte) ([]byte, int, error) {
	mgr, c, err := localClusterManager()
	if err != nil {
		return nil, 0, err
	}
	if password == "" {
		// The host keeps the password (QPOT_CLUSTER_PASSWORD or the 0600
		// cluster.secret), so it need not be typed where ps can see it.
		if err := mgr.UnlockFromSecret(); err != nil {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return nil, 0, fmt.Errorf("%w; pass --password", err)
			}
			fmt.Print("Enter cluster password: ")
			pw, rerr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if rerr != nil {
				return nil, 0, fmt.Errorf("failed to read password: %w", rerr)
			}
			password = string(pw)
		} else {
			password = mgr.Password()
		}
	}
	if err := mgr.UnlockPassword(password); err != nil {
		return nil, 0, fmt.Errorf("wrong cluster password")
	}
	port := cluster.DefaultClusterPort
	host := "127.0.0.1"
	if c.Config != nil {
		if c.Config.BindPort != 0 {
			port = c.Config.BindPort
		}
		// A cluster bound to one address listens only there.
		bind := strings.Trim(c.Config.BindAddr, "[]")
		if ip := net.ParseIP(bind); bind != "" && (ip == nil || !ip.IsUnspecified()) {
			host = bind
		}
	}
	base := fmt.Sprintf("%s://%s/api/v1/cluster", mgr.APIScheme(), net.JoinHostPort(host, strconv.Itoa(port)))
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Cluster-Password", password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := mgr.HTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot reach the local cluster API (is 'qpot up' / 'qpot serve' running?): %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, resp.StatusCode, fmt.Errorf("the cluster API is refusing this address after repeated wrong passwords; try again in 10 minutes")
	}
	return out, resp.StatusCode, nil
}

func newClusterRequestsCommand() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List pending join requests awaiting approval",
		Long:  "Show cluster join requests that supplied the correct password and are awaiting host approval, with the requester's source IP and hostname.",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, code, err := clusterAPIRequest(http.MethodGet, "/pending", password, nil)
			if err != nil {
				return err
			}
			if code == http.StatusUnauthorized {
				return fmt.Errorf("authentication failed: wrong cluster password")
			}
			var pending []cluster.PendingJoin
			if err := json.Unmarshal(out, &pending); err != nil {
				return fmt.Errorf("unexpected response: %s", string(out))
			}
			if len(pending) == 0 {
				fmt.Println("No pending join requests.")
				return nil
			}
			fmt.Printf("%-22s  %-16s  %-16s  %-15s  %s\n", "REQUEST ID", "HOSTNAME", "SOURCE IP", "INSTANCE", "REQUESTED")
			for _, p := range pending {
				fmt.Printf("%-22s  %-16s  %-16s  %-15s  %s\n",
					p.RequestID, truncate(termSafe(p.NodeName), 16), termSafe(p.SourceIP),
					truncate(termSafe(p.InstanceName), 15), p.RequestedAt.Format(time.RFC3339))
			}
			fmt.Println("\nApprove with: qpot cluster approve <request-id>")
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "cluster password (default: QPOT_CLUSTER_PASSWORD or the stored cluster secret)")
	return cmd
}

func newClusterApproveCommand() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "approve <request-id>",
		Short: "Approve a pending join request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reqBody, _ := json.Marshal(map[string]string{"request_id": args[0]})
			out, code, err := clusterAPIRequest(http.MethodPost, "/approve", password, reqBody)
			if err != nil {
				return err
			}
			switch code {
			case http.StatusOK:
				fmt.Printf("[OK] Approved join request %s\n", args[0])
				return nil
			case http.StatusUnauthorized:
				return fmt.Errorf("authentication failed: wrong cluster password")
			default:
				return fmt.Errorf("approve failed (%d): %s", code, string(out))
			}
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "cluster password (default: QPOT_CLUSTER_PASSWORD or the stored cluster secret)")
	return cmd
}

func newClusterRemoveCommand() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "remove <node-id>",
		Short: "Remove a node from the cluster (enrollment host only)",
		Long: "Remove a member, for example one that is compromised or gone for good. Run it on the enrollment host: " +
			"it signs the removal with the cluster CA, and every member refuses the node from then on, whatever credentials " +
			"it kept. The node IDs are listed by 'qpot cluster nodes'. A removed node can only come back by joining again.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reqBody, _ := json.Marshal(map[string]string{"node_id": args[0]})
			out, code, err := clusterAPIRequest(http.MethodPost, "/remove", password, reqBody)
			if err != nil {
				return err
			}
			switch code {
			case http.StatusOK:
				fmt.Printf("[OK] Removed node %s; the other members refuse it once gossip reaches them\n", termSafe(args[0]))
				return nil
			case http.StatusUnauthorized:
				return fmt.Errorf("authentication failed: wrong cluster password")
			default:
				return fmt.Errorf("remove failed (%d): %s", code, termSafe(strings.TrimSpace(string(out))))
			}
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "cluster password (default: QPOT_CLUSTER_PASSWORD or the stored cluster secret)")
	return cmd
}

func newClusterDenyCommand() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "deny <request-id>",
		Short: "Deny a pending join request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reqBody, _ := json.Marshal(map[string]string{"request_id": args[0]})
			out, code, err := clusterAPIRequest(http.MethodPost, "/deny", password, reqBody)
			if err != nil {
				return err
			}
			switch code {
			case http.StatusNoContent, http.StatusOK:
				fmt.Printf("[OK] Denied join request %s\n", args[0])
				return nil
			case http.StatusUnauthorized:
				return fmt.Errorf("authentication failed: wrong cluster password")
			default:
				return fmt.Errorf("deny failed (%d): %s", code, string(out))
			}
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "cluster password (default: QPOT_CLUSTER_PASSWORD or the stored cluster secret)")
	return cmd
}

// hasBinary reports whether name resolves on PATH. Used for best-effort
// detection of optional desktop notification helpers.
func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// getLocalIP attempts to get the host's primary outbound IPv4 address.
// It walks every up, non-loopback interface and returns the first usable
// IPv4 it finds. Falls back to 127.0.0.1 only when nothing better is
// available — that previous unconditional return broke cluster join's
// auto-detection.
func getLocalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			return ip4.String()
		}
	}
	return "127.0.0.1"
}

// truncate shortens s to at most maxLen characters, appending "..." when
// truncated. Safely handles maxLen <= 3 (no room for the ellipsis) and
// non-positive values, both of which previously caused a panic from a
// negative slice index.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// newDockerCommand creates the docker management command for QPot containers.
func newDockerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "docker",
		Short: "Manage QPot Docker containers",
		Long:  "Inspect and manage Docker containers belonging to QPot instances",
	}

	cmd.AddCommand(newDockerPSCommand())
	cmd.AddCommand(newDockerLogsCommand())
	cmd.AddCommand(newDockerRestartCommand())

	return cmd
}

// dockerContainerInfo holds parsed container information from docker ps output.
type dockerContainerInfo struct {
	ID       string
	Image    string
	Status   string
	Ports    string
	Names    string
	Health   string
	Honeypot string
}

// runDockerPS executes docker ps and returns QPot-related containers.
// QPot containers are identified by the qpot.instance label that the generated
// compose file sets on every service. (Container names are "<instance>_<svc>",
// which need not contain "qpot", so a name check found nothing.)
func runDockerPS(ctx context.Context) ([]dockerContainerInfo, error) {
	args := []string{
		"ps", "-a",
		"--filter", "label=" + qpotInstanceLabel,
		"--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}",
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	// Capture stderr alongside stdout so a "permission denied on docker.sock"
	// or "daemon not running" message reaches the user instead of being
	// dropped by exec.Cmd.Output().
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if isDockerNotFound(err) {
			return nil, fmt.Errorf("docker not found: install Docker to use this command")
		}
		stderrMsg := strings.TrimSpace(stderr.String())
		if stderrMsg != "" {
			return nil, fmt.Errorf("docker ps failed: %w: %s", err, stderrMsg)
		}
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	var containers []dockerContainerInfo
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		name := parts[4]
		info := dockerContainerInfo{
			ID:     parts[0],
			Image:  parts[1],
			Status: parts[2],
			Ports:  parts[3],
			Names:  name,
		}
		// Derive honeypot name from container name (format: <instance>_<honeypot>)
		info.Honeypot = deriveHoneypot(name)
		// Extract health status from Status field (e.g. "Up 5 minutes (healthy)")
		info.Health = extractHealth(info.Status)
		containers = append(containers, info)
	}
	return containers, nil
}

// qpotInstanceLabel is set by the generated compose file on every QPot service.
const qpotInstanceLabel = "qpot.instance"

// requireQPotContainer returns an error unless the named container carries the
// qpot.instance label, so `qpot docker logs/restart` never touch other
// containers on the host.
func requireQPotContainer(ctx context.Context, name string) error {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--type", "container",
		"--format", "{{index .Config.Labels \""+qpotInstanceLabel+"\"}}", name).Output()
	if err != nil {
		if isDockerNotFound(err) {
			return fmt.Errorf("docker not found: install Docker to use this command")
		}
		return fmt.Errorf("container '%s' not found", name)
	}
	if strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("container '%s' is not a QPot container (no %s label)", name, qpotInstanceLabel)
	}
	return nil
}

// isDockerNotFound returns true when the error indicates the docker binary
// is missing from PATH. We prefer the typed sentinel exec.ErrNotFound (set
// by exec.LookPath / Cmd.Start when the binary cannot be resolved) over a
// substring match, because a real docker error such as
// "Error response from daemon: No such image" used to false-positive here
// and report "docker not found" to the user.
func isDockerNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	// On Windows the error from a missing binary surfaces as os.PathError
	// wrapping ERROR_FILE_NOT_FOUND; check that explicitly.
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	return false
}

// deriveHoneypot extracts the honeypot name from a QPot container name.
// Container names follow the pattern <instance>_<service> or
// <instance>-<service>-1 (compose v2).
func deriveHoneypot(name string) string {
	// Remove trailing "-1" suffix added by compose v2.
	trimmed := strings.TrimSuffix(name, "-1")
	// Split on underscore first (docker compose v1 style).
	parts := strings.SplitN(trimmed, "_", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	// Try hyphen split (compose v2 style: instance-service).
	hparts := strings.SplitN(trimmed, "-", 2)
	if len(hparts) == 2 {
		return hparts[1]
	}
	return trimmed
}

// extractHealth parses the health state from a docker status string such as
// "Up 2 minutes (healthy)" or "Up 3 hours (unhealthy)".
func extractHealth(status string) string {
	lower := strings.ToLower(status)
	switch {
	case strings.Contains(lower, "(healthy)"):
		return "healthy"
	case strings.Contains(lower, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(lower, "(health: starting)"):
		return "starting"
	case strings.HasPrefix(lower, "up"):
		return "running"
	case strings.HasPrefix(lower, "exited"):
		return "exited"
	default:
		return "unknown"
	}
}

func newDockerPSCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "List QPot Docker containers",
		Long:  "Show all QPot-related Docker containers with their status and honeypot type",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			containers, err := runDockerPS(ctx)
			if err != nil {
				return err
			}

			if len(containers) == 0 {
				fmt.Println("No QPot containers found. Run 'qpot up' to start an instance.")
				return nil
			}

			// Print table header.
			fmt.Printf("%-20s %-35s %-25s %-25s %-15s %-10s\n",
				"CONTAINER", "IMAGE", "STATUS", "PORTS", "HONEYPOT", "HEALTH")
			fmt.Println(strings.Repeat("-", 135))
			for _, c := range containers {
				name := c.Names
				if len(name) > 20 {
					name = name[:17] + "..."
				}
				image := c.Image
				if len(image) > 35 {
					image = image[:32] + "..."
				}
				status := c.Status
				if len(status) > 25 {
					status = status[:22] + "..."
				}
				ports := c.Ports
				if len(ports) > 25 {
					ports = ports[:22] + "..."
				}
				hp := c.Honeypot
				if len(hp) > 15 {
					hp = hp[:12] + "..."
				}
				fmt.Printf("%-20s %-35s %-25s %-25s %-15s %-10s\n",
					name, image, status, ports, hp, c.Health)
			}
			return nil
		},
	}
}

func newDockerLogsCommand() *cobra.Command {
	var tail int

	cmd := &cobra.Command{
		Use:   "logs [container]",
		Short: "Show logs for a QPot container",
		Long:  "Tail logs for a specific QPot Docker container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			containerName := args[0]

			// Safety check: only act on containers QPot created.
			if err := requireQPotContainer(ctx, containerName); err != nil {
				return err
			}

			dockerArgs := []string{"logs", "--tail", fmt.Sprintf("%d", tail), containerName}
			dockerCmd := exec.CommandContext(ctx, "docker", dockerArgs...)
			// Container output carries attacker input.
			stdout, stderr := &termSafeWriter{w: os.Stdout}, &termSafeWriter{w: os.Stderr}
			dockerCmd.Stdout, dockerCmd.Stderr = stdout, stderr
			err := dockerCmd.Run()
			stdout.Flush()
			stderr.Flush()
			if err != nil {
				if isDockerNotFound(err) {
					return fmt.Errorf("docker not found: install Docker to use this command")
				}
				return fmt.Errorf("failed to get logs for container '%s': %w", containerName, err)
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&tail, "tail", "n", 50, "number of lines to show from end of logs")
	return cmd
}

func newDockerRestartCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "restart [container]",
		Short: "Restart a QPot container",
		Long:  "Restart a specific QPot Docker container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			containerName := args[0]

			// Safety check: only act on containers QPot created.
			if err := requireQPotContainer(ctx, containerName); err != nil {
				return err
			}

			dockerCmd := exec.CommandContext(ctx, "docker", "restart", containerName)
			dockerCmd.Stdout = os.Stdout
			dockerCmd.Stderr = os.Stderr

			if err := dockerCmd.Run(); err != nil {
				if isDockerNotFound(err) {
					return fmt.Errorf("docker not found: install Docker to use this command")
				}
				return fmt.Errorf("failed to restart container '%s': %w", containerName, err)
			}

			fmt.Printf("[OK] Container '%s' restarted\n", containerName)
			return nil
		},
	}
}

// newConfigCommand opens the instance config file in the user's editor
// or, with --print, just prints the absolute path. Useful for quickly
// editing per-instance settings without remembering ~/.qpot/instances/...
func newConfigCommand() *cobra.Command {
	var (
		instanceName string
		printOnly    bool
	)

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Open or show the instance configuration file",
		Long: `Open the instance config file (config.yaml) in $EDITOR / $VISUAL.
On Windows, falls back to notepad.exe; on Linux/macOS, falls back to nano,
then vim, then vi. Use --print to just show the path without launching an editor.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateInstanceName(instanceName); err != nil {
				return err
			}

			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			path := cfg.ConfigPath
			if path == "" {
				return fmt.Errorf("instance %q has no resolved config path", instanceName)
			}

			// Persist the file if it doesn't exist yet — config.Load returns
			// a Default() in-memory config when the file is missing, but the
			// editor needs an actual file to open. Save() also creates the
			// parent directory.
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				if err := config.Save(cfg); err != nil {
					return fmt.Errorf("failed to materialise config file: %w", err)
				}
				slog.Info("Created default config", "path", path)
			} else if err != nil {
				return fmt.Errorf("failed to stat config file: %w", err)
			}

			if printOnly {
				fmt.Println(path)
				return nil
			}

			editor := pickEditor()
			if editor == "" {
				// No editor available — fall back to printing the path so the
				// command still does something useful in headless contexts.
				fmt.Printf("[INFO] No editor found in $EDITOR/$VISUAL/PATH; config is at:\n  %s\n", path)
				return nil
			}

			editorCmd := exec.Command(editor, path)
			editorCmd.Stdin = os.Stdin
			editorCmd.Stdout = os.Stdout
			editorCmd.Stderr = os.Stderr
			if err := editorCmd.Run(); err != nil {
				return fmt.Errorf("editor %q exited with error: %w", editor, err)
			}
			fmt.Printf("[OK] Saved %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().BoolVar(&printOnly, "print", false, "print the config path and exit, do not open an editor")

	return cmd
}

// pickEditor resolves an editor binary across platforms: prefers $VISUAL
// then $EDITOR (POSIX convention), then a sensible OS-specific fallback
// chain. Returns "" if nothing is available — Arch minimal installs may
// have no editor in PATH at all, and headless servers commonly do too.
func pickEditor() string {
	for _, env := range []string{"VISUAL", "EDITOR"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			// $EDITOR may legitimately contain flags ("nano -w"). Use the
			// command name to verify it resolves on PATH, but return the
			// raw value so the user's flags are preserved — ah, but
			// exec.Command needs argv0 separately. Keep it simple: only
			// support a single binary. If users want flags they can set a
			// wrapper script.
			fields := strings.Fields(v)
			if len(fields) > 0 {
				if _, err := exec.LookPath(fields[0]); err == nil {
					return fields[0]
				}
			}
		}
	}
	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{"notepad.exe", "code", "vim", "nano"}
	} else {
		// Order tuned for Arch + Linux + macOS minimal installs.
		candidates = []string{"nano", "vim", "vi", "code", "micro"}
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}

// newDBCommand wires the existing MigrationManager into the CLI so users
// can inspect schema state, apply migrations, or roll back without
// modifying auto_migrate in their config and restarting QPot.
func newDBCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database management commands",
		Long:  "Inspect schema versions and run/rollback migrations against the configured database backend.",
	}

	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Manage database schema migrations",
	}
	migrate.AddCommand(newDBMigrateStatusCommand())
	migrate.AddCommand(newDBMigrateUpCommand())
	migrate.AddCommand(newDBMigrateDownCommand())
	cmd.AddCommand(migrate)

	return cmd
}

// openMigrationManager loads the instance config, opens the database, and
// returns a configured MigrationManager. Caller is responsible for closing
// the database via the returned cleanup function.
func openMigrationManager(ctx context.Context, instanceName string) (*database.MigrationManager, database.Database, func(), error) {
	if err := validateInstanceName(instanceName); err != nil {
		return nil, nil, nil, err
	}

	cfg, err := config.Load(instanceName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load config: %w", err)
	}

	db, err := database.New(cfg.DatabaseClient())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to construct database driver: %w", err)
	}

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.Connect(connectCtx); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	mgr := database.NewMigrationManager(db)
	for _, m := range database.GetCoreMigrations() {
		mgr.Register(m)
	}

	cleanup := func() {
		// Close the backend connection/pool. The Database interface DOES declare
		// Close() (database.go), and every backend (pgxpool, clickhouse, ES)
		// implements it; without this each `qpot db migrate` invocation leaked the
		// opened connection pool until process exit.
		_ = db.Close()
	}
	return mgr, db, cleanup, nil
}

func newDBMigrateStatusCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			mgr, _, cleanup, err := openMigrationManager(ctx, instanceName)
			if err != nil {
				return err
			}
			defer cleanup()

			status, err := mgr.Status(ctx)
			if err != nil {
				return fmt.Errorf("failed to read migration status: %w", err)
			}

			fmt.Printf("Current schema version: %d\n", status.CurrentVersion)
			fmt.Printf("Latest available:       %d\n", status.LatestVersion)
			fmt.Printf("Pending:                %d\n", status.PendingCount)
			fmt.Println()
			fmt.Printf("%-8s %-32s %-10s\n", "VERSION", "NAME", "APPLIED")
			fmt.Println(strings.Repeat("-", 55))
			for _, m := range status.Migrations {
				applied := "no"
				if m.Applied {
					applied = "yes"
				}
				fmt.Printf("%-8d %-32s %-10s\n", m.Version, m.Name, applied)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

func newDBMigrateUpCommand() *cobra.Command {
	var (
		instanceName  string
		targetVersion int
	)
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Apply pending migrations",
		Long:  "Apply all pending migrations, or use --to <version> to migrate to a specific version.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			mgr, _, cleanup, err := openMigrationManager(ctx, instanceName)
			if err != nil {
				return err
			}
			defer cleanup()

			if targetVersion > 0 {
				if err := mgr.MigrateToVersion(ctx, targetVersion); err != nil {
					return fmt.Errorf("migrate to %d failed: %w", targetVersion, err)
				}
				fmt.Printf("[OK] Migrated to version %d\n", targetVersion)
				return nil
			}

			if err := mgr.Migrate(ctx); err != nil {
				return fmt.Errorf("migrate failed: %w", err)
			}
			current, err := mgr.GetCurrentVersion(ctx)
			if err != nil {
				return fmt.Errorf("failed to read current version: %w", err)
			}
			fmt.Printf("[OK] Schema is at version %d\n", current)
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().IntVar(&targetVersion, "to", 0, "migrate to a specific version (0 = latest)")
	return cmd
}

func newDBMigrateDownCommand() *cobra.Command {
	var (
		instanceName string
		yes          bool
	)
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Roll back the most recent migration",
		Long:  "Roll back the database schema by one migration. Pass --yes to skip the confirmation prompt.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			mgr, _, cleanup, err := openMigrationManager(ctx, instanceName)
			if err != nil {
				return err
			}
			defer cleanup()

			current, err := mgr.GetCurrentVersion(ctx)
			if err != nil {
				return fmt.Errorf("failed to read current version: %w", err)
			}
			if current == 0 {
				fmt.Println("No migrations applied; nothing to roll back.")
				return nil
			}

			if !yes {
				fmt.Printf("Roll back version %d? This is destructive. [y/N]: ", current)
				var resp string
				fmt.Scanln(&resp)
				if resp != "y" && resp != "Y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			target := current - 1
			if err := mgr.MigrateToVersion(ctx, target); err != nil {
				return fmt.Errorf("rollback failed: %w", err)
			}
			fmt.Printf("[OK] Rolled back to version %d\n", target)
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip confirmation prompt")
	return cmd
}

// localBaseURL builds the URL of this instance's local API. A wildcard or empty
// bind address is rewritten to a loopback address so the CLI actually connects
// (dialing 0.0.0.0 / :: is not portable, notably on Windows).
func localBaseURL(cfg *config.Config) string {
	host := cfg.WebUI.BindAddr
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	// JoinHostPort brackets IPv6 literals: "http://::1:8080" does not parse.
	return "http://" + net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(cfg.WebUI.Port))
}

// canaryAPI performs an authenticated request against the local canary API and
// decodes a JSON object response. A connection failure is reported as the
// server not running, since canaries are runtime objects owned by `qpot up`.
func canaryAPI(ctx context.Context, cfg *config.Config, qpotID, method, path string, body interface{}) (map[string]interface{}, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, localBaseURL(cfg)+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-QPot-ID", qpotID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server not reachable (run 'qpot up' first): %w", err)
	}
	defer resp.Body.Close()
	payload := map[string]interface{}{}
	// A body is optional (e.g. some errors); ignore decode EOF on empty bodies.
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := payload["error"].(string)
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return payload, nil
}

// loadCanaryContext loads config + QPot ID for a canary subcommand.
func loadCanaryContext(instanceName string) (*config.Config, string, error) {
	cfg, err := config.Load(instanceName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load config: %w", err)
	}
	id, err := instance.LoadID(instanceName)
	if err != nil || id == nil {
		return nil, "", fmt.Errorf("no QPot ID for instance %q (run 'qpot up' first)", instanceName)
	}
	return cfg, id.ID, nil
}

// newCanaryCommand creates the canary (honeytoken) management command.
func newCanaryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "canary",
		Short: "Manage canaries (honeytokens)",
		Long: `Mint and manage canaries: decoy artifacts that alert on monitored interactions.

A trip records a beacon request or a watched value in captured honeypot event
fields. It does not by itself prove theft or compromise. QPot marks trips as
critical for investigation. The false-positive rate has not been measured:
previews, link scanners and authorized tests can also trigger trips.

Kinds:
  web   a beacon URL; a GET or HEAD reaching it can trip the canary. Plant it
        as a fake bookmark, a config comment or an "internal admin" URL.
  file  an HTML document that attempts to fetch its beacon when opened.
        Plant it on a share. Download it with 'qpot canary artifact'.
  aws   a realistic but fake AWS key pair, watched in captured honeypot
        event fields.

Reading a credential or file alone need not alert. Direct use against real AWS
is not monitored. All kinds can also trip on watched values in captured events;
this needs intelligence.enabled and is checked every 10 seconds, with the
worker matching anything that check missed.
No recorded trips does not prove no access occurred.

Canaries are runtime objects owned by a running instance, so 'qpot up' must be
active. Set 'canary.base_url' in the instance config so minted URLs point at
wherever this QPot is reachable.

Examples:
  qpot canary create --kind aws  --name ci-runner --memo "planted in Jenkins"
  qpot canary create --kind web  --name wiki-link --memo "fake intranet bookmark"
  qpot canary create --kind file --name q4-salaries --memo "HR share"
  qpot canary list
  qpot canary trips
  qpot canary artifact cnry_abc123 --out bait.html
  qpot canary rm cnry_abc123`,
	}

	cmd.AddCommand(newCanaryCreateCommand())
	cmd.AddCommand(newCanaryListCommand())
	cmd.AddCommand(newCanaryTripsCommand())
	cmd.AddCommand(newCanaryArtifactCommand())
	cmd.AddCommand(newCanaryRemoveCommand())
	return cmd
}

func newCanaryCreateCommand() *cobra.Command {
	var instanceName, kind, name, memo string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a new canary",
		RunE: func(cmd *cobra.Command, args []string) error {
			if kind == "" {
				return fmt.Errorf("--kind is required (web, file, or aws)")
			}
			cfg, id, err := loadCanaryContext(instanceName)
			if err != nil {
				return err
			}
			resp, err := canaryAPI(cmd.Context(), cfg, id, http.MethodPost, "/api/canaries",
				map[string]string{"kind": kind, "name": name, "memo": memo})
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Created canary %v (%v)\n", resp["id"], resp["kind"])
			if name != "" {
				fmt.Printf("     Name: %s\n", name)
			}
			if memo != "" {
				fmt.Printf("     Memo: %s\n", memo)
			}
			if u, ok := resp["url"].(string); ok {
				fmt.Printf("     URL:  %s\n", u)
				if strings.HasPrefix(u, "/c/") {
					fmt.Println("     [!] Set canary.base_url in the config so this URL is plantable off-host.")
				}
			}
			if ak, ok := resp["access_key_id"].(string); ok {
				fmt.Printf("     AWS_ACCESS_KEY_ID:     %s\n", ak)
				fmt.Printf("     AWS_SECRET_ACCESS_KEY: %v\n", resp["secret_access_key"])
				fmt.Println("     Plant this pair where only an intruder would find it.")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().StringVarP(&kind, "kind", "k", "", "canary kind: web, file, or aws (required)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "human label")
	cmd.Flags().StringVarP(&memo, "memo", "m", "", "where it is planted (shown with every trip)")
	return cmd
}

func newCanaryListCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List canaries",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, id, err := loadCanaryContext(instanceName)
			if err != nil {
				return err
			}
			resp, err := canaryAPI(cmd.Context(), cfg, id, http.MethodGet, "/api/canaries", nil)
			if err != nil {
				return err
			}
			items, _ := resp["canaries"].([]interface{})
			if len(items) == 0 {
				fmt.Println("No canaries. Mint one with 'qpot canary create'.")
				return nil
			}
			// planted canaries have longer IDs (cnry_ + 24 hex) and kinds
			fmt.Printf("%-29s %-10s %-36s %-6s %s\n", "ID", "KIND", "NAME", "TRIPS", "MEMO")
			for _, it := range items {
				c, _ := it.(map[string]interface{})
				fmt.Printf("%-29v %-10v %-36v %-6v %v\n",
					c["id"], c["kind"], truncField(c["name"], 36), c["trips"], termSafe(fmt.Sprint(c["memo"])))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

func newCanaryTripsCommand() *cobra.Command {
	var instanceName string
	var limit int
	cmd := &cobra.Command{
		Use:   "trips",
		Short: "Show recent canary trips (the alerts)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, id, err := loadCanaryContext(instanceName)
			if err != nil {
				return err
			}
			path := fmt.Sprintf("/api/canaries/trips?limit=%d", limit)
			resp, err := canaryAPI(cmd.Context(), cfg, id, http.MethodGet, path, nil)
			if err != nil {
				return err
			}
			trips, _ := resp["trips"].([]interface{})
			if len(trips) == 0 {
				fmt.Println("No trips recorded. This does not rule out access outside monitored events.")
				return nil
			}
			fmt.Printf("%-24s %-9s %-16s %-20s %s\n", "TIME", "CHANNEL", "SOURCE IP", "NAME", "DETAIL")
			for _, it := range trips {
				t, _ := it.(map[string]interface{})
				fmt.Printf("%-24v %-9v %-16v %-20v %v\n",
					t["time"], t["channel"], termSafe(fmt.Sprint(t["source_ip"])), truncField(t["name"], 20), termSafe(fmt.Sprint(t["detail"])))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().IntVar(&limit, "limit", 100, "max trips to show")
	return cmd
}

func newCanaryArtifactCommand() *cobra.Command {
	var instanceName, out string
	cmd := &cobra.Command{
		Use:   "artifact <canary-id>",
		Short: "Download the document artifact for a file canary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, id, err := loadCanaryContext(instanceName)
			if err != nil {
				return err
			}
			reqCtx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			url := localBaseURL(cfg) + "/api/canaries/artifact?id=" + args[0]
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			req.Header.Set("X-QPot-ID", id)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("server not reachable (run 'qpot up' first): %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("artifact download failed: %s", resp.Status)
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if err != nil {
				return err
			}
			dest, write := out, os.WriteFile
			if dest == "" {
				dest = artifactFileName(resp.Header.Get("Content-Disposition"), args[0]+".html")
				write = func(name string, data []byte, _ os.FileMode) error {
					err := writeNewFile(name, data)
					if errors.Is(err, os.ErrExist) {
						return fmt.Errorf("%s already exists; choose a file with -o", name)
					}
					return err
				}
			}
			if err := write(dest, data, 0o600); err != nil {
				return fmt.Errorf("write artifact: %w", err)
			}
			fmt.Printf("[OK] Wrote %s (%d bytes). Plant it where an intruder would look.\n", dest, len(data))
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output file (default: the canary's suggested name)")
	return cmd
}

// artifactFileName is the file name the server suggests in a
// Content-Disposition header, reduced to a plain name in the working
// directory, or fallback when there is no usable one. The response comes from
// whatever answers on the web UI port, so its name is never used as a path,
// and only a name of the shape QPot gives (letters, digits, '-', '_' and '.',
// as in "Q4-salaries.html") is taken: never a hidden file such as .bashrc, and
// never a name Windows reads as a device (CON, NUL, COM1, ...).
func artifactFileName(contentDisposition, fallback string) string {
	_, params, err := mime.ParseMediaType(contentDisposition)
	if err != nil {
		return fallback
	}
	name := params["filename"]
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if !artifactNamePattern.MatchString(name) || strings.HasSuffix(name, ".") {
		return fallback
	}
	stem, _, _ := strings.Cut(strings.ToUpper(name), ".")
	if windowsDeviceName.MatchString(stem) {
		return fallback
	}
	return name
}

var (
	artifactNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	windowsDeviceName   = regexp.MustCompile(`^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$`)
)

// writeNewFile writes data to a file that must not exist yet, so a name the
// server suggested never replaces one of the user's files.
func writeNewFile(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func newCanaryRemoveCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:     "rm <canary-id>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a canary",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, id, err := loadCanaryContext(instanceName)
			if err != nil {
				return err
			}
			if _, err := canaryAPI(cmd.Context(), cfg, id, http.MethodDelete,
				"/api/canaries?id="+args[0], nil); err != nil {
				return err
			}
			fmt.Printf("[OK] Removed canary %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

// truncField renders a value as a string truncated to n runes for table output.
func truncField(v interface{}, n int) string {
	s := termSafe(fmt.Sprintf("%v", v))
	if len(s) > n {
		if n > 1 {
			return s[:n-1] + "…"
		}
		return s[:n]
	}
	return s
}
