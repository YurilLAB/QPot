package instance

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/sshbackend"
	"gopkg.in/yaml.v3"
)

// Each organization is a set of disposable, real services behind one ingress
// SSH connection. Names and credentials describe the same organization in every
// pool slot, while the networks, state and reset boundary remain per slot.
const sshOrganizationDBImage = "docker.io/library/postgres:15-bookworm@sha256:19b8449e2187e8a174b40c8832a7ed9da45813b74c2779b1c614e7e7d0ee47f0"

type sshOrgCell struct {
	App, Database, Backup, Network                        string
	AppHostname, DBHostname, BackupHostname               string
	AppAliases, DBAliases, BackupAliases                  []string
	AppSceneJSON, BackupSceneJSON                         string
	DBUsername, DBPassword, DBName, DBImage               string
	DBInitSQLPath, DBLogDir, BackupUsersCSV, BackupKeyDir string
}

type sshOrganization struct {
	name, domain, appHostname, database, dbUser, dbPassword, adminPassword string
	backupUser, backupPassword                                             string
	clientPrivate, clientPublic, hostPrivate, hostPublic                   string
}

func sshOrganizationRequested(cfg *config.Config) bool {
	hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot)
	return ok && strings.TrimSpace(hp.CustomConfig["environment"]) == "organization"
}

func sshOrganizationEnabled(cfg *config.Config) bool {
	return sshProxyEnabled(cfg) && sshOrganizationRequested(cfg)
}

// validateSSHHostnames keeps pool identities and planted host relationships
// unambiguous. Docker registers container hostnames as case-insensitive DNS
// names even without explicit network aliases.
func validateSSHHostnames(cfg *config.Config) error {
	if !sshProxyEnabled(cfg) {
		return nil
	}
	hostname := sshBackendHostname(cfg)
	if sshOrganizationRequested(cfg) {
		hostname = newSSHOrganization(cfg).appHostname
	}
	// The broker joins every cell and dials its ingress service ID. Reusing
	// any finite cell ID can make distinct leases resolve to one guest in
	// either mode, including after pool growth.
	if sshCellApp(strings.ToLower(hostname)) != "" {
		return fmt.Errorf("honeypots.ssh-proxy.stealth.fake_hostname %q conflicts with an SSH pool service; choose a distinct application hostname", hostname)
	}
	cells, err := sshOrgCells(cfg)
	if err != nil {
		return err
	}
	for _, cell := range cells {
		reserved := map[string]bool{
			"localhost": true, "localhost.localdomain": true,
			"ip6-localhost": true, "ip6-loopback": true,
			sshProxyHoneypot: true, cell.Database: true, cell.Backup: true,
		}
		for _, alias := range append(append([]string{}, cell.DBAliases...), cell.BackupAliases...) {
			reserved[strings.ToLower(alias)] = true
		}
		for _, alias := range cell.AppAliases {
			if reserved[strings.ToLower(alias)] || sshCellApp(strings.ToLower(alias)) != "" {
				return fmt.Errorf("honeypots.ssh-proxy.stealth.fake_hostname %q conflicts with an organization service or loopback alias; choose a distinct application hostname", cell.AppHostname)
			}
		}
	}
	return nil
}

// sshCellServiceNames returns the entire reset/stop boundary of a configured
// ingress backend. It deliberately does not require Enabled: disabling a
// honeypot saves that flag before stopping its companions.
func sshCellServiceNames(cfg *config.Config, app string) []string {
	if !sshOrganizationRequested(cfg) {
		return []string{app}
	}
	return []string{app, app + "-db", app + "-backup"}
}

func allSSHCellServiceNames(cfg *config.Config) []string {
	var out []string
	for _, app := range sshBackendServiceNames(cfg) {
		out = append(out, sshCellServiceNames(cfg, app)...)
	}
	return out
}

func newSSHOrganization(cfg *config.Config) sshOrganization {
	d := canary.NewDeriver(deceptionSeed(cfg)).Sub("ssh-organization")
	name := canary.Pick(d, "organization", baitOrgs)
	client := d.Ed25519Key("backup-client")
	host := d.Ed25519Key("backup-host")
	appHostname := "app01"
	if hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot); ok && hp.Stealth.FakeHostname != "" {
		if name := sanitizeHostname(hp.Stealth.FakeHostname); name != "" {
			appHostname = name
		}
	}
	return sshOrganization{
		name: name, domain: name + ".internal", appHostname: appHostname,
		database: canary.Pick(d, "database", baitDBNames), dbUser: "app_service",
		dbPassword: d.HumanPassword("database-password"), adminPassword: d.HumanPassword("database-admin"),
		backupUser: "bkp", backupPassword: d.HumanPassword("backup-password"),
		clientPrivate: string(canary.MarshalEd25519PrivateKey(client, "operations backup", binary.BigEndian.Uint32(d.Bytes("client-check", 4)))),
		clientPublic:  canary.AuthorizedKey(canary.Ed25519PublicBlob(client.Public().(ed25519.PublicKey)), "operations backup"),
		hostPrivate:   string(canary.MarshalEd25519PrivateKey(host, "", binary.BigEndian.Uint32(d.Bytes("host-check", 4)))),
		hostPublic:    canary.AuthorizedKey(canary.Ed25519PublicBlob(host.Public().(ed25519.PublicKey)), ""),
	}
}

// sshOrgCells describes companion wiring using private location metadata, without
// contacting Docker. Compose rendering precedes auxiliary-file creation, and
// deriving the backup host identity here keeps known_hosts correct on first boot.
func sshOrgCells(cfg *config.Config) ([]sshOrgCell, error) {
	if !sshOrganizationEnabled(cfg) {
		return nil, nil
	}
	store, err := planSSHStore(cfg)
	if err != nil {
		return nil, err
	}
	s := newSSHOrganization(cfg)
	appAliases := []string{"app", "app." + s.domain, s.appHostname}
	if !strings.Contains(s.appHostname, ".") {
		appAliases = append(appAliases, s.appHostname+"."+s.domain)
	}
	seenAliases := map[string]bool{}
	var aliases []string
	for _, alias := range appAliases {
		if !seenAliases[alias] {
			aliases = append(aliases, alias)
			seenAliases[alias] = true
		}
	}
	var out []sshOrgCell
	for _, app := range sshBackendServiceNames(cfg) {
		appPlan, backupPlan := s.manifests()
		appJSON, _ := json.Marshal(appPlan)       // only finite strings/slices; cannot fail
		backupJSON, _ := json.Marshal(backupPlan) // only finite strings/slices; cannot fail
		out = append(out, sshOrgCell{
			App: app, Database: app + "-db", Backup: app + "-backup", Network: sshBackendNetwork(app),
			AppHostname: s.appHostname, DBHostname: "db01", BackupHostname: "backup01",
			AppAliases: aliases, DBAliases: []string{"db", "db01", "db01." + s.domain},
			BackupAliases: []string{"backup", "backup01", "backup01." + s.domain},
			AppSceneJSON:  string(appJSON), BackupSceneJSON: string(backupJSON),
			DBUsername: "postgres", DBPassword: s.adminPassword, DBName: s.database, DBImage: sshOrganizationDBImage,
			DBInitSQLPath:  store.database(app),
			DBLogDir:       store.current(app + "-db"),
			BackupUsersCSV: s.backupUser + ":" + s.backupPassword,
			BackupKeyDir:   store.keys(true),
		})
	}
	return out, nil
}

func sqlString(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func (s sshOrganization) manifests() (sshbackend.Manifest, sshbackend.Manifest) {
	database := sshbackend.Database{Host: "db", Database: s.database, User: s.dbUser, Password: s.dbPassword}
	backup := sshbackend.Backup{Host: "backup", User: s.backupUser, Password: s.backupPassword}
	app := sshbackend.Manifest{Version: 1, Role: "app", Organization: s.name, Database: database, Backup: backup}
	archive := sshbackend.Manifest{Version: 1, Role: "backup", Organization: s.name, Database: database, Backup: backup}
	app.Directories = []sshbackend.Directory{
		{Path: "/srv/app", Mode: 0o755, Owner: "root"},
		{Path: "/srv/app/.ssh", Mode: 0o700, Owner: "root"},
	}
	var env strings.Builder
	for _, entry := range [][2]string{{"APP_ORGANIZATION", s.name}, {"DB_HOST", "db"}, {"DB_PORT", "5432"},
		{"DB_NAME", s.database}, {"DB_USER", s.dbUser}, {"DB_PASSWORD", s.dbPassword},
		{"BACKUP_HOST", "backup"}, {"BACKUP_USER", s.backupUser}, {"BACKUP_PASSWORD", s.backupPassword}} {
		fmt.Fprintf(&env, "%s=%s\n", entry[0], shellQuote(entry[1]))
	}
	knownHosts := "backup,backup01,backup01." + s.domain + " " + s.hostPublic + "\n"
	app.Files = []sshbackend.File{
		{Path: "/srv/app/.env", Mode: 0o644, Owner: "root", Content: env.String()},
		{Path: "/srv/app/.ssh/id_ed25519", Mode: 0o600, Owner: "root", Content: s.clientPrivate},
		{Path: "/srv/app/.ssh/id_ed25519.pub", Mode: 0o644, Owner: "root", Content: s.clientPublic + "\n"},
		{Path: "/srv/app/.ssh/known_hosts", Mode: 0o644, Owner: "root", Content: knownHosts},
		{Path: "/srv/app/README", Mode: 0o644, Owner: "root", Content: fmt.Sprintf(
			"%s operations\n\nDatabase: db01.%s:5432/%s\nBackup storage: %s@backup01.%s:/srv/backups/%s\n\nConnection settings are in /srv/app/.env.\nRun /usr/local/bin/backup-db as root for a current compressed SQL backup.\n", title(s.name), s.domain, s.database, s.backupUser, s.domain, s.database)},
		{Path: "/usr/local/bin/backup-db", Mode: 0o755, Owner: "root", Content: s.backupScript()},
	}
	archive.Directories = []sshbackend.Directory{
		{Path: "/home/" + s.backupUser + "/.ssh", Mode: 0o700, Owner: s.backupUser},
		{Path: "/srv/backups/" + s.database, Mode: 0o750, Owner: s.backupUser},
	}
	archive.Files = []sshbackend.File{
		{Path: "/home/" + s.backupUser + "/.ssh/authorized_keys", Mode: 0o600, Owner: s.backupUser, Content: s.clientPublic + "\n"},
		{Path: "/srv/backups/" + s.database + "/initial.sql", Mode: 0o640, Owner: s.backupUser, Content: s.schemaSQL()},
		{Path: "/srv/backups/README", Mode: 0o644, Owner: s.backupUser, Content: fmt.Sprintf(
			"%s database backups\n\nThe initial SQL export is kept under %s/.\nCurrent compressed exports arrive from the application host's backup-db tool.\n", title(s.name), s.database)},
	}
	return app, archive
}

func (s sshOrganization) backupScript() string {
	return `#!/bin/sh
set -eu
. /srv/app/.env
stamp=$(date -u +%Y%m%dT%H%M%SZ)
tmp=$(mktemp /tmp/backup-db.XXXXXX)
trap 'rm -f "$tmp" "$tmp.gz"' EXIT HUP INT TERM
PGPASSWORD="$DB_PASSWORD" pg_dump --no-owner --no-privileges --host="$DB_HOST" --username="$DB_USER" "$DB_NAME" >"$tmp"
gzip -c "$tmp" >"$tmp.gz"
ssh -i /srv/app/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=/srv/app/.ssh/known_hosts "$BACKUP_USER@$BACKUP_HOST" "cat > /srv/backups/$DB_NAME/$DB_NAME-$stamp.sql.gz" <"$tmp.gz"
printf 'Backup completed: %s@%s:/srv/backups/%s/%s-%s.sql.gz\n' "$BACKUP_USER" "$BACKUP_HOST" "$DB_NAME" "$DB_NAME" "$stamp"
`
}

// schemaSQL is valid PostgreSQL input and the initial backup's exact schema/data.
// Ordinary SQL mutations subsequently use the real database; no SQL is emulated.
func (s sshOrganization) schemaSQL() string {
	return fmt.Sprintf(`-- %s application data
BEGIN;
CREATE TABLE public.assets (id integer PRIMARY KEY, hostname text NOT NULL, role text NOT NULL, status text NOT NULL);
INSERT INTO public.assets VALUES
  (1, 'app.%s', 'application', 'active'),
  (2, 'db01.%s', 'database', 'active'),
  (3, 'backup01.%s', 'backup', 'active');
CREATE TABLE public.backup_targets (id integer PRIMARY KEY, hostname text NOT NULL, directory text NOT NULL, retention_days integer NOT NULL);
INSERT INTO public.backup_targets VALUES (1, 'backup01.%s', '/srv/backups/%s', 14);
COMMIT;
`, title(s.name), s.domain, s.domain, s.domain, s.domain, s.database)
}

func (s sshOrganization) initSQL() string {
	return fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s;\nGRANT CONNECT ON DATABASE %s TO %s;\nGRANT USAGE, CREATE ON SCHEMA public TO %s;\nSET ROLE %s;\n", s.dbUser, sqlString(s.dbPassword), s.database, s.dbUser, s.dbUser, s.dbUser) + s.schemaSQL()
}

// prepareSSHOrganization materializes only trusted auxiliary files mounted by
// the generated cell. Neither database contents nor backend files are persisted
// here: those live in disposable container layers/tmpfs and reset as a group.
func prepareSSHOrganization(cfg *config.Config) error {
	if !sshOrganizationEnabled(cfg) {
		return nil
	}
	s := newSSHOrganization(cfg)
	cells, err := sshOrgCells(cfg)
	if err != nil {
		return err
	}
	for _, cell := range cells {
		if err := os.MkdirAll(filepath.Dir(cell.DBInitSQLPath), 0o750); err != nil {
			return fmt.Errorf("prepare organization database configuration: %w", err)
		}
		if err := writeSecretFile(cell.DBInitSQLPath, []byte(s.initSQL())); err != nil {
			return fmt.Errorf("write organization database configuration: %w", err)
		}
		// PostgreSQL runs as999; this is a read-only mount containing synthetic
		// initialization data, not an operator credential or management secret.
		if err := os.Chmod(cell.DBInitSQLPath, 0o644); err != nil { // #nosec G302 -- decoy initialization mounted read-only into UID999.
			return err
		}
		for _, service := range []string{cell.Database, cell.Backup} {
			if err := prepareSSHLogDir(cfg.DataPath, service); err != nil {
				return fmt.Errorf("prepare organization logs: %w", err)
			}
		}
		if err := os.MkdirAll(cell.BackupKeyDir, 0o755); err != nil {
			return fmt.Errorf("prepare backup host identity: %w", err)
		}
		key := filepath.Join(cell.BackupKeyDir, "ssh_host_ed25519_key")
		if err := writeSecretFile(key, []byte(s.hostPrivate)); err != nil {
			return fmt.Errorf("write backup host identity: %w", err)
		}
		if err := os.WriteFile(key+".pub", []byte(s.hostPublic+"\n"), 0o644); err != nil { // #nosec G306 -- public host key.
			return err
		}
		if err := ensureSSHHostKeys(cell.BackupKeyDir); err != nil {
			return fmt.Errorf("prepare backup host keys: %w", err)
		}
	}
	return nil
}

// sshLayout contains only known, instance-owned cell services from a rendered
// Compose file. It is used instead of the newly saved config when retiring an
// old organization/count, and by the recycler after live settings changes.
type sshLayout struct {
	Groups map[string][]string
	Broker bool
	Images map[string]string
}

func sshCellApp(service string) string {
	for n := 1; n <= maxSSHBackends; n++ {
		app := fmt.Sprintf("ssh-backend-%d", n)
		if service == app || service == app+"-db" || service == app+"-backup" {
			return app
		}
	}
	return ""
}

func parseSSHLayout(data []byte, instanceName string) (sshLayout, error) {
	out := sshLayout{Groups: map[string][]string{}, Images: map[string]string{}}
	if len(data) == 0 {
		return out, nil
	}
	if len(data) > 8<<20 {
		return out, fmt.Errorf("rendered Compose exceeds the cell-layout limit")
	}
	var doc struct {
		Services map[string]struct {
			Labels yaml.Node `yaml:"labels"`
			Image  string    `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return out, fmt.Errorf("read rendered SSH cell layout: %w", err)
	}
	for name, service := range doc.Services {
		labels := sshLayoutLabels(service.Labels)
		if labels["qpot.instance"] != instanceName {
			continue
		}
		honeypot := labels["qpot.honeypot"]
		if name == sshProxyHoneypot && honeypot == sshProxyHoneypot {
			out.Broker = true
			out.Images[name] = service.Image
			continue
		}
		app := sshCellApp(name)
		if app != "" && (honeypot == "ssh-backend" || honeypot == sshProxyHoneypot) {
			out.Groups[app] = append(out.Groups[app], name)
			out.Images[name] = service.Image
		}
	}
	for app, members := range out.Groups {
		sort.Strings(members)
		// A companion without its ingress is not an active lease. Keep it in
		// the layout for retirement, but discovery checks the app's presence.
		out.Groups[app] = members
	}
	return out, nil
}

func sshLayoutLabels(node yaml.Node) map[string]string {
	var labels map[string]string
	if err := node.Decode(&labels); err == nil {
		return labels
	}
	// Compose also accepts ["key=value", ...]. A manual change to this legal
	// representation must not break another service's configuration update.
	var entries []string
	if err := node.Decode(&entries); err != nil || len(entries) > 256 {
		return nil
	}
	labels = map[string]string{}
	for _, entry := range entries {
		if key, value, ok := strings.Cut(entry, "="); ok {
			labels[key] = value
		}
	}
	return labels
}

func readSSHLayout(composePath, instanceName string) (sshLayout, error) {
	data, err := os.ReadFile(composePath)
	if os.IsNotExist(err) {
		return sshLayout{Groups: map[string][]string{}}, nil
	}
	if err != nil {
		return sshLayout{}, err
	}
	return parseSSHLayout(data, instanceName)
}

// lockSSHCells serializes host-controlled layout changes and whole-cell reset
// across the CLI and control-plane processes. The OS releases it on exit, so a
// crashed process cannot leave a stale-directory lock that disables recycling.
func lockSSHCells(ctx context.Context, dataPath string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dataPath, ".ssh-cells.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		ok, err := trySSHCellLock(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if ok {
			return f, nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = f.Close()
			return nil, fmt.Errorf("wait for SSH cell lifecycle: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// retireSSHCells removes only obsolete instance-owned HiFi cells using the old
// Compose snapshot. Whole touched cells are discarded before the new layout is
// written, so a surviving app cannot retain another cell's old database/files.
func retireSSHCells(ctx context.Context, cfg *config.Config, oldCompose []byte) error {
	layout, err := parseSSHLayout(oldCompose, cfg.InstanceName)
	if err != nil {
		return err
	}
	desired := map[string]bool{}
	if sshProxyEnabled(cfg) {
		for _, name := range allSSHCellServiceNames(cfg) {
			desired[name] = true
		}
	}
	var remove []string
	for _, members := range layout.Groups {
		obsolete := false
		for _, name := range members {
			obsolete = obsolete || !desired[name]
		}
		if obsolete {
			remove = append(remove, members...)
		}
	}
	if layout.Broker && !sshProxyEnabled(cfg) {
		remove = append(remove, sshProxyHoneypot)
	}
	if len(remove) == 0 {
		return nil
	}
	sort.Strings(remove)
	f, err := os.CreateTemp(cfg.DataPath, ".ssh-layout-*.yaml")
	if err != nil {
		return err
	}
	oldPath := f.Name()
	defer os.Remove(oldPath)
	if _, err := f.Write(oldCompose); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	// Their session capture leaves with the containers: stop and convert it.
	if err := stopSSHServices(ctx, oldPath, remove); err != nil {
		return fmt.Errorf("retire prior SSH cells: %w", err)
	}
	brokerLog, err := sshBrokerSessionLog(cfg)
	if err != nil {
		return fmt.Errorf("retire prior SSH cells: %w", err)
	}
	if err := drainSSHCaptures(ctx, cfg.DataPath, cfg.InstanceName, brokerLog, remove); err != nil {
		return fmt.Errorf("retire prior SSH cells: they are stopped but kept: %w", err)
	}
	args := append([]string{"compose", "-f", oldPath, "rm", "--stop", "--force"}, remove...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = cfg.DataPath
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("retire prior SSH cells: %w: %s", err, output)
	}
	return nil
}
