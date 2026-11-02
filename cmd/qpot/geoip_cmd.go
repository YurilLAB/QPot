package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/geo"
	"github.com/qpot/qpot/internal/instance"
)

// geoipContainerDir is where the collector sees <DataPath>/geoip (the data
// path is mounted read-only at /data).
const geoipContainerDir = "/data/geoip"

// provisionGeoIP downloads the free DB-IP Lite country database into the
// instance, points the collector at it and, when unset, places the sensor on
// the attack map from the host's time zone. It changes cfg but does not save.
func provisionGeoIP(ctx context.Context, cfg *config.Config) error {
	dest := filepath.Join(cfg.DataPath, "geoip", geo.DBIPCountryFile)
	dctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if err := geo.DownloadDBIPCountry(dctx, nil, dest, time.Now().UTC()); err != nil {
		return err
	}
	cfg.Collector.GeoIPDBPath = geoipContainerDir + "/" + geo.DBIPCountryFile
	if cfg.AttackMap.Country == "" {
		if c, ok := geo.HostCountry(); ok {
			cfg.AttackMap.Country = c.Code
		}
	}
	return nil
}

func newGeoIPCommand() *cobra.Command {
	var instanceName, country string
	cmd := &cobra.Command{
		Use:   "geoip",
		Short: "Manage the GeoIP database used for countries and the attack map",
	}
	update := &cobra.Command{
		Use:   "update",
		Short: "Download the current DB-IP Lite country database and use it",
		Long: `Download the free DB-IP Lite country database (monthly, ~4 MB, CC BY 4.0)
into the instance, point the collector at it, and restart the collector if the
instance is running. New events are then tagged with the attacker's country,
which the attack map and dashboards use. Run it monthly for fresh data.

` + geo.DBIPAttribution,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(instanceName)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			if err := setMapCountry(cfg, country); err != nil {
				return err
			}
			if err := provisionGeoIP(cmd.Context(), cfg); err != nil {
				return err
			}
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return err
			}
			if err := mgr.ReloadCollector(cmd.Context()); err != nil {
				return err
			}
			fmt.Printf("[OK] GeoIP database installed for instance '%s'", instanceName)
			if cfg.AttackMap.Country != "" {
				fmt.Printf(" (attack map location: %s)", cfg.AttackMap.Country)
			}
			fmt.Printf("\n     %s\n", geo.DBIPAttribution)
			return nil
		},
	}
	update.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	update.Flags().StringVar(&country, "country", "", "two-letter country code of this sensor, for the attack map")
	cmd.AddCommand(update)
	return cmd
}

// setMapCountry sets where the attack map draws this sensor; empty keeps the
// current setting.
func setMapCountry(cfg *config.Config, code string) error {
	if code == "" {
		return nil
	}
	c, ok := geo.Lookup(code)
	if !ok {
		return fmt.Errorf("unknown country code %q (use a two-letter ISO code such as DE or US)", code)
	}
	cfg.AttackMap.Country = c.Code
	return nil
}
