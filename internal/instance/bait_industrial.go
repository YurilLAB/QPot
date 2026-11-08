package instance

// Industrial bait is an archive kept on a Linux support host. It does not add
// a controller filesystem, claim a Windows engineering installation, or imply
// that Cowrie can reach Conpot. Only the selected device's model and actual
// protocol families are shared; addresses and maintenance accounts are synthetic.

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qpot/qpot/internal/canary"
)

const industrialRoot = "/srv/ot"

type industrialEndpoint struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
}

type industrialAsset struct {
	ID        string               `json:"asset_id"`
	Role      string               `json:"role"`
	Model     string               `json:"model"`
	Address   string               `json:"address"`
	Protocols []string             `json:"protocols"`
	Endpoints []industrialEndpoint `json:"endpoints"`
}

type industrialInventory struct {
	Version    int               `json:"schema_version"`
	RecordedAt string            `json:"recorded_at"`
	SourceHost string            `json:"source_host"`
	RecordType string            `json:"record_type"`
	Assets     []industrialAsset `json:"assets"`
}

// industrialEndpoints associates ports with protocols, rather than suggesting
// every protocol in the catalog is spoken on every port of a device.
func industrialEndpoints(p ConpotDeviceProfile) []industrialEndpoint {
	protocol := map[string]map[int]string{
		"plc_modbus":          {502: "Modbus/TCP"},
		"IEC104":              {2404: "IEC 60870-5-104", 20000: "DNP3", 161: "SNMP"},
		"beckhoff_cx":         {4840: "OPC UA", 48898: "ADS", 48899: "ADS discovery"},
		"guardian_ast":        {10001: "Tank gauge protocol"},
		"kamstrup_382":        {1025: "Kamstrup metering", 50100: "Kamstrup management"},
		"building_automation": {47808: "BACnet/IP", 3671: "KNXnet/IP"},
		"hart_gateway":        {5094: "HART-IP"},
		"iccp":                {102: "ICCP / TASE.2"},
		"ipmi":                {623: "IPMI 2.0"},
	}[p.ID]
	endpoints := make([]industrialEndpoint, 0, len(p.TCP)+len(p.UDP))
	for _, transport := range []struct {
		name  string
		ports []int
	}{{"tcp", p.TCP}, {"udp", p.UDP}} {
		for _, port := range transport.ports {
			endpoints = append(endpoints, industrialEndpoint{transport.name, port, protocol[port]})
		}
	}
	return endpoints
}

func industrialAssetID(p ConpotDeviceProfile) string {
	return map[string]string{
		"plc_modbus": "plc01", "IEC104": "rtu01", "beckhoff_cx": "plc01",
		"guardian_ast": "tank01", "kamstrup_382": "meter01", "building_automation": "bms01",
		"hart_gateway": "fieldgw01", "iccp": "controlcom01", "ipmi": "bmc01",
	}[p.ID]
}

// buildIndustrial uses the existing bait plan renderer, key generation and
// canary registry. The JSON/CSV are local maintenance formats, not fabricated
// proprietary project files or a promise of running industrial applications.
func (s *baitScene) buildIndustrial() {
	p := ConpotProfile(s.cfg)
	assetID := industrialAssetID(p)
	if assetID == "" {
		// An invalid direct config is rejected before deployment; do not invent
		// a different controller for it while a caller inspects its plan.
		return
	}
	s.d = s.d.Sub("industrial")
	archive := s.db
	archive.Alias = "archive01"
	archive.FQDN = archive.Alias + "." + s.domain
	archive.User = "svc_otbackup"
	asset := industrialAsset{ID: assetID, Role: p.Category, Model: p.Model, Address: s.monitor.IP,
		Protocols: p.Protocols, Endpoints: industrialEndpoints(p)}
	// sshFiles is shared with the ops builder; with aws=true it writes one
	// remote-host entry only. No AWS files are created by this builder.
	s.db, s.aws = archive, true
	s.keyComment = "ot-maintenance@" + s.org
	s.sshFiles()
	s.plan.Hosts = append(s.plan.Hosts,
		baitHost{Names: []string{archive.Alias, archive.FQDN, archive.IP}, IP: archive.IP},
		baitHost{Names: []string{assetID, assetID + "." + s.domain, asset.Address}, IP: asset.Address})

	created := s.at("ot-created", 0.18, 0.25)
	exportAt := s.at("ot-export", 0.42, 0.54)
	backupAt := s.at("ot-backup", 0.58, 0.68)
	exportDir := industrialRoot + "/exports/" + assetID
	for _, dir := range []string{industrialRoot, industrialRoot + "/exports", exportDir,
		industrialRoot + "/maintenance", industrialRoot + "/backups"} {
		s.dir(dir, "root", 0o755, created)
	}

	inventory := industrialInventory{Version: 1, RecordedAt: "{{date:%Y-%m-%dT%H:%M:%SZ}}",
		SourceHost: "{{host}}", RecordType: "maintenance reference", Assets: []industrialAsset{asset}}
	b, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("industrial inventory: %v", err))
	}
	inventoryPath := industrialRoot + "/inventory.json"
	s.file(baitFile{ID: "ot_inventory", Path: inventoryPath, Owner: "root", Mode: 0o644,
		At: exportAt, Text: string(b) + "\n"})

	var comms strings.Builder
	w := csv.NewWriter(&comms)
	_ = w.Write([]string{"asset_id", "address", "transport", "port", "protocol"})
	for _, ep := range asset.Endpoints {
		_ = w.Write([]string{assetID, asset.Address, ep.Transport, fmt.Sprint(ep.Port), ep.Protocol})
	}
	w.Flush() // strings.Builder cannot fail.
	commsPath := exportDir + "/communications.csv"
	s.file(baitFile{Path: commsPath, Owner: "root", Mode: 0o644, At: exportAt, Text: comms.String()})

	notesPath := industrialRoot + "/maintenance/handover.txt"
	notes := fmt.Sprintf("Maintenance handover - %s\n\nReference asset: %s (%s), %s\n"+
		"Communications record: %s\nInventory: %s\n"+
		"These are support copies from the last maintenance window, not live polling data.\n"+
		"Full configuration backups and firmware are held offline by the maintenance contractor.\n"+
		"Confirm the current address and approved change window with operations before connecting.\n"+
		"The support host keeps reference exports; configuration changes use the device vendor's management tools.\n\n"+
		"Archive host: %s\nArchive account: %s\nSSH identity: /root/.ssh/id_ed25519\n"+
		"Transfer credentials: /root/.netrc (root only)\n"+
		"Last reference export: {{date:%%Y-%%m-%%d@ot_inventory}}\n",
		s.org, assetID, p.Model, p.Category, commsPath, inventoryPath, archive.FQDN, archive.User)
	s.file(baitFile{Path: notesPath, Owner: "root", Mode: 0o644, At: exportAt, Text: notes})
	s.file(baitFile{Path: industrialRoot + "/README.txt", Owner: "root", Mode: 0o644, At: created,
		Text: "OT maintenance reference archive\n\nInventory format: schema_version 1, assets with model, role, private address and service endpoints.\n" +
			"exports/ contains communications records; maintenance/handover.txt records the archive procedure.\n" +
			"backups/ contains dated text snapshots of the inventory and communications records.\n"})

	backupPath := industrialRoot + "/backups/" + assetID + "-reference-{{date:%Y%m%d}}.txt.gz"
	archivedInventory := strings.ReplaceAll(string(b), "{{date:%Y-%m-%dT%H:%M:%SZ}}", "{{date:%Y-%m-%dT%H:%M:%SZ@ot_inventory}}")
	backupText := "Maintenance reference snapshot\nRecorded: {{date:%Y-%m-%dT%H:%M:%SZ@ot_inventory}}\n\n" +
		inventoryPath + "\n" + archivedInventory + "\n\n" + commsPath + "\n" + comms.String()
	s.file(baitFile{ID: "ot_backup", Path: backupPath, Owner: "root", Mode: 0o640, At: backupAt,
		Gzip: true, Text: backupText})
	s.file(baitFile{Path: industrialRoot + "/maintenance/backup.log", Owner: "root", Mode: 0o644,
		At: backupAt, Text: "{{date:%Y-%m-%dT%H:%M:%SZ@ot_backup}} reference package stored: " +
			industrialRoot + "/backups/" + assetID + "-reference-{{date:%Y%m%d@ot_backup}}.txt.gz\n"})
	password := s.d.HumanPassword("archive-password")
	s.file(baitFile{Path: "/root/.netrc", Owner: "root", Mode: 0o600, At: created,
		Text: "machine " + archive.FQDN + "\n  login " + archive.User + "\n  password " + password + "\n"})
	s.plant(&canary.Canary{ID: s.d.ID("archive-password"), Kind: canary.KindCredential,
		Name: "cowrie bait: OT archive credential", Values: []string{password},
		Memo: s.memo("a synthetic OT archive password; trips when captured in a session, not on file read", "/root/.netrc")})

	s.plan.Links = append(s.plan.Links, baitLink{Path: s.home + "/ot", Target: industrialRoot, At: exportAt})
	s.file(baitFile{Path: s.home + "/.bash_history", Owner: s.user, Mode: 0o600, At: 1,
		Offset: -300, InPlace: true, Text: "cd ~/ot\nls -l exports\ncat maintenance/handover.txt\ncat inventory.json\nexit\n"})
	s.file(baitFile{Path: "/root/.bash_history", Owner: "root", Mode: 0o600, At: 1,
		Offset: -60, InPlace: true, Text: "cd " + industrialRoot + "\ncat inventory.json\ncat " + commsPath +
			"\nzcat " + industrialRoot + "/backups/" + assetID + "-reference-{{date:%Y%m%d@ot_backup}}.txt.gz\nssh " + archive.Alias + "\nexit\n"})
}
