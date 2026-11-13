package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/access"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// accessContext returns the data folder and the QPot ID of an instance.
// Tests replace it.
var accessContext = func(name string) (dataPath, ownerKey string, err error) {
	cfg, err := config.Load(name)
	if err != nil {
		return "", "", fmt.Errorf("failed to load config: %w", err)
	}
	// The QPot ID is only compared with a new key, never printed here.
	if id, err := instance.LoadID(name); err == nil && id != nil {
		ownerKey = id.ID
	}
	return cfg.DataPath, ownerKey, nil
}

func newAccessCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Give other people their own key to this instance, with a role",
		Long: `An instance has one owner key, the QPot ID ('qpot id'), which can do
everything. 'qpot access' gives other people a key of their own:

  viewer   reads everything the web UI and API show
  analyst  a viewer who can also create and delete canaries and switch
           alert rules
  admin    everything the owner can do in the web UI: honeypots, their
           settings, restarts, disk cleanup

A member signs in to the web UI with their key exactly as the owner does with
the QPot ID. The key is printed once, when the member is added, and is stored
only as a hash: a lost key is replaced by removing the member and adding them
again. Removing a member locks their key out within seconds.

Every change made through the web API, and every request a role was refused,
is written to the audit log with the member's name ('qpot access log').

Members are managed here, on the host, and never through the web API.

  qpot access add alice --role viewer
  qpot access list
  qpot access remove alice
  qpot access log`,
	}
	cmd.PersistentFlags().StringVarP(&instanceName, "instance", "i", "default", "instance name")

	var role string
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a member and print their key, once",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dataPath, ownerKey, err := accessContext(instanceName)
			if err != nil {
				return err
			}
			key, err := access.Add(dataPath, args[0], access.Role(role), ownerKey)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Added %s as %s on instance %s.\n\n", args[0], role, instanceName)
			fmt.Fprintf(w, "  Key: %s\n\n", key)
			fmt.Fprintln(w, "This key is shown once and cannot be read back. Give it to them over a private")
			fmt.Fprintln(w, "channel: they sign in to the web UI with it. It works within a few seconds.")
			return nil
		},
	}
	add.Flags().StringVar(&role, "role", "viewer", "viewer, analyst or admin")

	list := &cobra.Command{
		Use:   "list",
		Short: "List the members and their roles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dataPath, _, err := accessContext(instanceName)
			if err != nil {
				return err
			}
			l, err := access.Load(dataPath)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if len(l.Members) == 0 {
				fmt.Fprintln(w, "No members: only the QPot ID signs in. Add one with: qpot access add <name> --role viewer")
				return nil
			}
			fmt.Fprintf(w, "%-32s %-8s %s\n", "NAME", "ROLE", "ADDED (UTC)")
			for _, m := range l.Members {
				fmt.Fprintf(w, "%-32s %-8s %s\n", m.Name, m.Role, m.Created.UTC().Format("2006-01-02 15:04"))
			}
			return nil
		},
	}

	remove := &cobra.Command{
		Use:     "remove <name>",
		Aliases: []string{"rm"},
		Short:   "Remove a member: their key stops working within seconds",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dataPath, _, err := accessContext(instanceName)
			if err != nil {
				return err
			}
			if err := access.Remove(dataPath, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s. Their key no longer signs in.\n", args[0])
			return nil
		},
	}

	var limit int
	var asJSON bool
	log := &cobra.Command{
		Use:   "log",
		Short: "Show who changed what through the web API, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > access.MaxAuditRead {
				return fmt.Errorf("--limit must be from 1 to %d", access.MaxAuditRead)
			}
			dataPath, _, err := accessContext(instanceName)
			if err != nil {
				return err
			}
			entries, err := access.ReadAudit(dataPath, limit)
			if err != nil {
				return err
			}
			if asJSON {
				if entries == nil {
					entries = []access.Entry{}
				}
				return printJSON(cmd, entries)
			}
			w := cmd.OutOrStdout()
			if len(entries) == 0 {
				fmt.Fprintln(w, "Nothing has been changed through the web API yet.")
				return nil
			}
			fmt.Fprintf(w, "%-20s %-20s %-8s %-7s %-6s %s\n", "TIME (UTC)", "WHO", "ROLE", "METHOD", "STATUS", "PATH")
			for _, e := range entries {
				status := fmt.Sprint(e.Status)
				if e.Denied {
					status += " refused: the role may not do this"
				}
				fmt.Fprintf(w, "%-20s %-20s %-8s %-7s %-6s %s\n", e.Time.UTC().Format("2006-01-02 15:04:05"), termSafe(e.Who), termSafe(string(e.Role)),
					termSafe(e.Method), strings.SplitN(status, " ", 2)[0], termSafe(e.Path)+strings.TrimPrefix(status, fmt.Sprint(e.Status)))
			}
			return nil
		},
	}
	log.Flags().IntVar(&limit, "limit", 50, "how many entries to show")
	log.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	cmd.AddCommand(add, list, remove, log)
	return cmd
}
