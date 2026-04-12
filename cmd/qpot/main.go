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
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/intelligence"
	"github.com/qpot/qpot/internal/server"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	rootCmd.AddCommand(newClusterCommand())
	rootCmd.AddCommand(newDockerCommand())

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
			showQPotIDPopup(qpotID.ID, cfg.WebUI.Port)

			if err := mgr.Start(ctx, detach); err != nil {
				return fmt.Errorf("failed to start instance: %w", err)
			}

			fmt.Printf("\n[OK] QPot instance '%s' started successfully\n", cfg.InstanceName)
			fmt.Printf("[INFO] QPot ID: %s\n", qpotID.ID)
			fmt.Printf("[INFO] Web UI: http://%s:%d\n", cfg.WebUI.BindAddr, cfg.WebUI.Port)
			fmt.Println("\nUse this QPot ID to track your honeypot activity in the Web UI")

			// Start the web server if the web UI is enabled.
			if cfg.WebUI.Enabled {
				webSrv, err := server.New(cfg)
				if err != nil {
					slog.Warn("Failed to create web server", "error", err)
				} else {
					go func() {
						if err := webSrv.Start(ctx); err != nil && err.Error() != "http: Server closed" {
							slog.Error("Web server error", "error", err)
						}
					}()
					slog.Info("Web server started", "addr", fmt.Sprintf("%s:%d", cfg.WebUI.BindAddr, cfg.WebUI.Port))
				}
			}

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


// newClusterCommand creates the cluster management command
func newClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage QPot clusters",
		Long:  "Initialize, join, and manage multi-instance QPot clusters with password authentication",
	}

	cmd.AddCommand(newClusterInitCommand())
	cmd.AddCommand(newClusterJoinCommand())
	cmd.AddCommand(newClusterStatusCommand())
	cmd.AddCommand(newClusterLeaveCommand())
	cmd.AddCommand(newClusterNodesCommand())

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
				cfg.AdvertiseAddr = bindAddr
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
			if err := mgr.Start(); err != nil {
				return fmt.Errorf("failed to start cluster manager: %w", err)
			}

			fmt.Printf("\n[OK] Cluster initialized successfully\n")
			fmt.Printf("     Cluster ID:   %s\n", c.ID)
			fmt.Printf("     Cluster Name: %s\n", c.Name)
			fmt.Printf("     Node ID:      %s\n", c.LocalNode.ID)
			fmt.Printf("     Bind Address: %s:%d\n", cfg.BindAddr, cfg.BindPort)
			fmt.Println("\n[IMPORTANT] Save your Cluster ID and Password!")
			fmt.Println("            Other nodes will need both to join.")
			fmt.Printf("\nTo join this cluster, run:\n")
			fmt.Printf("  qpot cluster join --id %s --seed %s:%d\n", c.ID, cfg.AdvertiseAddr, cfg.BindPort)

			return nil
		},
	}

	cmd.Flags().StringVarP(&clusterName, "name", "n", "", "Cluster name (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Cluster password (min 8 chars)")
	cmd.Flags().StringVar(&bindAddr, "bind-addr", "0.0.0.0", "Bind address for cluster communication")
	cmd.Flags().IntVar(&bindPort, "bind-port", cluster.DefaultClusterPort, "Bind port for cluster communication")
	cmd.MarkFlagRequired("name")

	return cmd
}

func newClusterJoinCommand() *cobra.Command {
	var (
		clusterID   string
		password    string
		seedNodes   []string
		nodeName    string
		nodeAddr    string
		nodePort    int
		qpotID      string
		instanceName string
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

			// Load instance info if available
			if instanceName == "" {
				instanceName = "default"
			}
			
			idObj, _ := instance.LoadID(instanceName)
			if idObj != nil {
				qpotID = idObj.ID
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
				QPotID:       qpotID,
				InstanceName: instanceName,
				Metadata:     make(map[string]string),
				Capabilities: []string{"honeypot", "sensor"},
			}

			// Join cluster
			c, err := mgr.JoinCluster(clusterID, password, localNode, seedNodes)
			if err != nil {
				return fmt.Errorf("failed to join cluster: %w", err)
			}

			// Start cluster manager
			if err := mgr.Start(); err != nil {
				return fmt.Errorf("failed to start cluster manager: %w", err)
			}

			fmt.Printf("\n[OK] Successfully joined cluster\n")
			fmt.Printf("     Cluster ID:   %s\n", c.ID)
			fmt.Printf("     Cluster Name: %s\n", c.Name)
			fmt.Printf("     Node ID:      %s\n", c.LocalNode.ID)
			fmt.Printf("     Total Nodes:  %d\n", len(c.Nodes))

			return nil
		},
	}

	cmd.Flags().StringVarP(&clusterID, "id", "i", "", "Cluster ID (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Cluster password")
	cmd.Flags().StringArrayVarP(&seedNodes, "seed", "s", nil, "Seed node addresses (format: host:port)")
	cmd.Flags().StringVar(&nodeName, "node-name", "", "Name for this node (default: hostname)")
	cmd.Flags().StringVar(&nodeAddr, "node-addr", "", "Address for this node (auto-detected if not set)")
	cmd.Flags().IntVar(&nodePort, "node-port", cluster.DefaultClusterPort, "Port for cluster communication")
	cmd.Flags().StringVar(&qpotID, "qpot-id", "", "QPot ID (auto-detected if not set)")
	cmd.Flags().StringVar(&instanceName, "instance", "default", "QPot instance name")
	cmd.MarkFlagRequired("id")
	cmd.MarkFlagRequired("seed")

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
			fmt.Printf("Status:        %s\n", map[bool]string{true: "running", false: "stopped"}[status.IsRunning])
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
					truncate(node.Name, 15),
					fmt.Sprintf("%s:%d", node.Address, node.Port),
					node.Status,
					node.Stats.TotalEvents)
			}

			return nil
		},
	}

	return cmd
}

// getLocalIP attempts to get the local IP address
func getLocalIP() string {
	// This is a simplified implementation
	// In production, use proper interface enumeration
	return "127.0.0.1"
}

// truncate truncates a string to max length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
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
// QPot containers are identified by names containing "qpot" or by the
// com.docker.compose.project label prefix.
func runDockerPS(ctx context.Context) ([]dockerContainerInfo, error) {
	// Use JSON format output to reliably parse each field.
	// We run two passes: one for running containers, one with -a for all.
	args := []string{
		"ps", "-a",
		"--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}",
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	if err != nil {
		// If docker is not installed, exec.Error with "executable file not found"
		if isDockerNotFound(err) {
			return nil, fmt.Errorf("docker not found: install Docker to use this command")
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
		// Filter to QPot containers only: name must contain "qpot" (case-insensitive).
		if !strings.Contains(strings.ToLower(name), "qpot") {
			continue
		}
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

// isDockerNotFound returns true when the error indicates docker is not installed.
func isDockerNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no such file")
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

			// Verify the container name contains "qpot" as a safety check.
			if !strings.Contains(strings.ToLower(containerName), "qpot") {
				return fmt.Errorf("container '%s' does not appear to be a QPot container (name must contain 'qpot')", containerName)
			}

			dockerArgs := []string{"logs", "--tail", fmt.Sprintf("%d", tail), containerName}
			dockerCmd := exec.CommandContext(ctx, "docker", dockerArgs...)
			dockerCmd.Stdout = os.Stdout
			dockerCmd.Stderr = os.Stderr

			if err := dockerCmd.Run(); err != nil {
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

			// Verify the container name contains "qpot" as a safety check.
			if !strings.Contains(strings.ToLower(containerName), "qpot") {
				return fmt.Errorf("container '%s' does not appear to be a QPot container (name must contain 'qpot')", containerName)
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
