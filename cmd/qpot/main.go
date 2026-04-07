// QPot - Safe, User-Friendly Honeypot Platform
// Main CLI entry point
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		slog.Error("qpot failed", "error", err)
		os.Exit(1)
	}
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
	}

	// Global flags
	var cfgFile string
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.qpot/config.yaml)")

	// Add commands
	rootCmd.AddCommand(newUpCommand())
	rootCmd.AddCommand(newDownCommand())
	rootCmd.AddCommand(newStatusCommand())
	rootCmd.AddCommand(newInstanceCommand())
	rootCmd.AddCommand(newHoneypotCommand())
	rootCmd.AddCommand(newLogsCommand())
	rootCmd.AddCommand(newIDCommand())

	return rootCmd.ExecuteContext(ctx)
}

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
			
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Load or generate QPot ID
			qpotID, err := instance.LoadID(instanceName)
			if err != nil {
				// Generate new ID
				qpotID, err = instance.GenerateID(instanceName)
				if err != nil {
					return fmt.Errorf("failed to generate QPot ID: %w", err)
				}
				qpotID.DataPath = cfg.DataPath
				if err := qpotID.Save(); err != nil {
					return fmt.Errorf("failed to save QPot ID: %w", err)
				}
			}
			cfg.QPotID = qpotID.ID

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}

			// Show QPot ID popup before starting
			showQPotIDPopup(qpotID.ID, cfg.WebUI.Port)

			if err := mgr.Start(ctx, detach); err != nil {
				return fmt.Errorf("failed to start instance: %w", err)
			}

			fmt.Printf("\n[OK] QPot instance '%s' started successfully\n", cfg.InstanceName)
			fmt.Printf("[INFO] QPot ID: %s\n", qpotID.ID)
			fmt.Printf("[INFO] Web UI: http://%s:%d\n", cfg.WebUI.BindAddr, cfg.WebUI.Port)
			fmt.Println("\nUse this QPot ID to track your honeypot activity in the Web UI")
			
			if !detach {
				fmt.Println("\nPress Ctrl+C to stop")
				<-ctx.Done()
				return mgr.Stop(context.Background())
			}
			return nil
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
			
			// Generate QPot ID
			qpotID, err := instance.GenerateID(name)
			if err != nil {
				return fmt.Errorf("failed to generate QPot ID: %w", err)
			}

			cfg := config.Default(name)
			cfg.QPotID = qpotID.ID
			
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			// Save QPot ID
			qpotID.DataPath = cfg.DataPath
			if err := qpotID.Save(); err != nil {
				return fmt.Errorf("failed to save QPot ID: %w", err)
			}

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}

			if err := mgr.Initialize(ctx); err != nil {
				return fmt.Errorf("failed to initialize instance: %w", err)
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
			honeypots := []struct {
				Name        string
				Description string
				Risk        string
				Port        int
			}{
				{"cowrie", "SSH/Telnet honeypot", "low", 2222},
				{"dionaea", "Malware capture honeypot", "medium", 21},
				{"conpot", "Industrial control systems honeypot", "low", 102},
				{"tanner", "Web application honeypot", "low", 80},
				{"adbhoney", "Android Debug Bridge honeypot", "low", 5555},
				{"endlessh", "SSH tarpit (slows attackers)", "low", 22},
				{"heralding", "Credential honeypot", "low", 110},
				{"honeyaml", "API honeypot", "low", 3000},
			}

			fmt.Println("Available honeypots:")
			fmt.Println("Name        Port  Risk   Description")
			fmt.Println("----------- ----- ------ ----------------------------------------")
			for _, hp := range honeypots {
				fmt.Printf("%-11s %5d %-6s %s\n", hp.Name, hp.Port, hp.Risk, hp.Description)
			}
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

			cfg.EnableHoneypot(hpName)
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Printf("[OK] Enabled honeypot '%s' for instance '%s'\n", hpName, instanceName)
			fmt.Println("     Run 'qpot up' to apply changes")
			
			// Auto-start if instance is running
			mgr, _ := instance.NewManager(cfg)
			if mgr != nil && mgr.IsRunning(ctx) {
				if err := mgr.StartHoneypot(ctx, hpName); err != nil {
					return fmt.Errorf("failed to start honeypot: %w", err)
				}
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

			cfg.DisableHoneypot(hpName)
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Printf("[OK] Disabled honeypot '%s' for instance '%s'\n", hpName, instanceName)
			
			// Auto-stop if instance is running
			mgr, _ := instance.NewManager(cfg)
			if mgr != nil && mgr.IsRunning(ctx) {
				if err := mgr.StopHoneypot(ctx, hpName); err != nil {
					return fmt.Errorf("failed to stop honeypot: %w", err)
				}
				fmt.Printf("[OK] Stopped honeypot '%s'\n", hpName)
			}
			
			return nil
		},
	}
	disableCmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	cmd.AddCommand(listCmd, enableCmd, disableCmd)

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
				fmt.Println(line)
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

// showQPotIDPopup displays a GUI notification with the QPot ID
func showQPotIDPopup(id string, webPort int) {
	// Build message
	title := "QPot Started"
	message := fmt.Sprintf("Your QPot ID:\n%s\n\nWeb UI: http://localhost:%d\n\nSave this ID to track your honeypot!", id, webPort)

	switch runtime.GOOS {
	case "windows":
		// Windows notification using PowerShell
		psCmd := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Information
$notify.Visible = $true
$notify.BalloonTipTitle = "%s"
$notify.BalloonTipText = @"
QPot ID: %s
Web UI: http://localhost:%d
"@
$notify.ShowBalloonTip(10000)
`, title, id, webPort)
		exec.Command("powershell", "-Command", psCmd).Start()

		// Also show message box for persistence
		msgCmd := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show("QPot ID: %s`+"\n"+`Web UI: http://localhost:%d", "QPot Started", "OK", "Information")`, id, webPort)
		go func() {
			time.Sleep(500 * time.Millisecond)
			exec.Command("powershell", "-Command", msgCmd).Start()
		}()

	case "darwin":
		// macOS notification using osascript
		script := fmt.Sprintf(`display notification "QPot ID: %s" with title "%s" subtitle "Web UI: http://localhost:%d"`, id, title, webPort)
		exec.Command("osascript", "-e", script).Start()

		// Also use alert
		alertScript := fmt.Sprintf(`display alert "%s" message "QPot ID: %s\n\nWeb UI: http://localhost:%d\n\nSave this ID to access your honeypot!" as informational buttons {"Copy ID", "OK"} default button "OK"`, title, id, webPort)
		go func() {
			time.Sleep(500 * time.Millisecond)
			exec.Command("osascript", "-e", alertScript).Start()
		}()

	default:
		// Linux - try multiple notification methods
		// notify-send
		exec.Command("notify-send", "-t", "10000", title, message).Start()
		
		// zenity
		go func() {
			time.Sleep(500 * time.Millisecond)
			zenityMsg := fmt.Sprintf("<big><b>Your QPot ID</b></big>\n\n<span font='monospace'>%s</span>\n\nWeb UI: http://localhost:%d\n\nSave this ID to track your honeypot!", id, webPort)
			exec.Command("zenity", "--info", "--title=QPot Started", "--width=400", "--text="+zenityMsg).Start()
		}()
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
