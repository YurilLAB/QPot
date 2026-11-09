// Command qpot-netguard keeps an instance's honeypot containers from opening
// connections to the networks around the docker host (see internal/netguard).
// It runs as a compose service in the host's network namespace with only
// CAP_NET_ADMIN, applies the guard's nftables table, and re-applies it on an
// interval so the table comes back if anything flushes it. Honeypot services
// wait for its healthcheck (`qpot-netguard check`) before they start.
//
// Configuration (environment):
//
//	QPOT_NETGUARD_TABLE     nftables table name (family inet), REQUIRED
//	QPOT_NETGUARD_IFACES    comma-separated honeypot bridge interfaces, REQUIRED
//	QPOT_NETGUARD_CELLS     optional private HiFi bridges (must be listed in IFACES)
//	QPOT_NETGUARD_MODE      "private" (default) or "all"
//	QPOT_NETGUARD_INTERVAL  re-apply interval (default "30s", 5s-10m)
//	QPOT_NETGUARD_RESOLV    resolv.conf listing the host's resolvers (default "/etc/resolv.conf")
//
// Commands: run (default), apply (once), check, remove.
//
// On exit it leaves the table in place: honeypots that outlive the guard stay
// fenced in. The table only matches the listed interfaces.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qpot/qpot/internal/netguard"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	spec, interval, err := specFromEnv()
	if err != nil {
		log.Error("bad configuration", "err", err)
		os.Exit(2)
	}
	switch cmd {
	case "apply":
		err = netguard.Apply(spec)
	case "check":
		err = netguard.Check(spec)
	case "check-cells":
		// Generated HiFi composes require this command in their healthcheck.
		// An older helper cannot silently ignore the private-cell policy.
		if len(spec.Cells) == 0 {
			err = fmt.Errorf("private cell interfaces are required")
		} else {
			err = netguard.Check(spec)
		}
	case "remove":
		err = netguard.Remove(spec.Table)
	case "run":
		err = run(log, spec, interval)
	default:
		err = fmt.Errorf("unknown command %q (run, apply, check, check-cells, remove)", cmd)
	}
	if err != nil {
		log.Error(cmd+" failed", "err", err)
		os.Exit(1)
	}
}

func specFromEnv() (netguard.Spec, time.Duration, error) {
	s := netguard.Spec{
		Table:  os.Getenv("QPOT_NETGUARD_TABLE"),
		Ifaces: netguard.ParseIfaces(os.Getenv("QPOT_NETGUARD_IFACES")),
		Cells:  netguard.ParseIfaces(os.Getenv("QPOT_NETGUARD_CELLS")),
		Mode:   netguard.Mode(os.Getenv("QPOT_NETGUARD_MODE")),
	}
	if s.Mode == "" {
		s.Mode = netguard.ModePrivate
	}
	interval := 30 * time.Second
	if v := os.Getenv("QPOT_NETGUARD_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 5*time.Second || d > 10*time.Minute {
			return s, 0, fmt.Errorf("QPOT_NETGUARD_INTERVAL %q: want 5s-10m", v)
		}
		interval = d
	}
	path := os.Getenv("QPOT_NETGUARD_RESOLV")
	if path == "" {
		path = "/etc/resolv.conf"
	}
	if f, err := os.Open(path); err == nil {
		s.DNS, err = netguard.ParseResolvConf(f)
		f.Close()
		if err != nil {
			return s, 0, fmt.Errorf("%s: %w", path, err)
		}
	}
	return s, interval, s.Validate()
}

// run applies the table, then re-applies it every interval until stopped. A
// failed first apply is fatal (the healthcheck never passes, so no honeypot
// starts); later failures are logged and retried.
func run(log *slog.Logger, spec netguard.Spec, interval time.Duration) error {
	if err := netguard.Apply(spec); err != nil {
		return err
	}
	log.Info("guard applied", "table", spec.Table, "ifaces", spec.Ifaces, "mode", spec.Mode, "dns", spec.DNS)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("stopping; table left in place", "table", spec.Table)
			return nil
		case <-tick.C:
			if err := netguard.Check(spec); err != nil {
				log.Warn("guard drifted, re-applying", "err", err)
			}
			if err := netguard.Apply(spec); err != nil {
				log.Error("re-apply failed", "err", err)
			}
		}
	}
}
