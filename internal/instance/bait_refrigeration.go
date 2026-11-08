package instance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/refrigeration"
)

// refrigerationDeviceSeed is the only seed supplied to the standalone device.
// A compromised emulator must not receive the base seed from which another
// honeypot's identity or canary values are derived.
func refrigerationDeviceSeed(cfg *config.Config) string {
	sum := sha256.Sum256([]byte("qpot-refrigeration-device-v1\x00" + deceptionSeed(cfg)))
	return hex.EncodeToString(sum[:])
}

func refrigerationArchiveCanary(cfg *config.Config) *canary.Canary {
	seed := refrigerationDeviceSeed(cfg)
	_, password := refrigeration.MaintenanceCredential(seed)
	d := canary.NewDeriver(seed).Sub("maintenance-watch")
	return &canary.Canary{
		ID: d.ID("archive-credential"), Kind: canary.KindCredential,
		Name:   "refrigeration bait: maintenance archive credential",
		Values: []string{password}, Enabled: true, Planted: true,
		Memo: "Refrigeration maintenance export .netrc; optional Cowrie industrial support copy in /root/.netrc. " +
			"Synthetic archive account: alerts on captured credential reuse, not export download or file read.",
	}
}

// buildRefrigeration plants a Linux support-host reference and the same
// archive credential exported by the standalone refrigeration controller.
// HTTP is the only advertised management service; no PLC or fieldbus port is
// invented for the controller, and the support copy is not a live connection.
func (s *baitScene) buildRefrigeration() {
	identity, err := refrigeration.IdentityForSeed(refrigerationDeviceSeed(s.cfg), refrigerationSiteProfile(s.cfg))
	if err != nil {
		// Rejecting invalid direct configuration belongs to deployment. A
		// caller inspecting its files must not get an invented fallback site.
		return
	}
	s.d = s.d.Sub("refrigeration-support")
	created, exported := s.at("created", 0.18, 0.25), s.at("export", 0.45, 0.6)
	exportDir := industrialRoot + "/exports/refrigeration01"
	for _, p := range []string{industrialRoot, industrialRoot + "/exports", exportDir, industrialRoot + "/maintenance"} {
		s.dir(p, "root", 0o755, created)
	}
	asset := industrialAsset{
		ID: "refrigeration01", Role: "Refrigeration supervisory controller", Model: "Danfoss " + identity.Model,
		Address: s.monitor.IP, Protocols: []string{"HTTP management"},
		Endpoints: []industrialEndpoint{{Transport: "tcp", Port: 8080, Protocol: "HTTP management"}},
	}
	inventory := struct {
		industrialInventory
		Controller refrigeration.Identity `json:"controller"`
	}{industrialInventory{Version: 1, RecordedAt: "{{date:%Y-%m-%dT%H:%M:%SZ}}",
		SourceHost: "{{host}}", RecordType: "maintenance reference", Assets: []industrialAsset{asset}}, identity}
	b, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("refrigeration inventory: %v", err))
	}
	s.file(baitFile{ID: "refrigeration_inventory", Path: industrialRoot + "/inventory.json", Owner: "root", Mode: 0o644, At: exported, Text: string(b) + "\n"})
	s.file(baitFile{Path: exportDir + "/communications.csv", Owner: "root", Mode: 0o644, At: exported,
		Text: "asset_id,address,transport,port,protocol\nrefrigeration01," + asset.Address + ",tcp,8080,HTTP management\n"})
	s.file(baitFile{Path: industrialRoot + "/maintenance/handover.txt", Owner: "root", Mode: 0o644, At: exported,
		Text: "Refrigeration maintenance handover\n\nReference controller: Danfoss " + identity.Model + ", firmware " + identity.Firmware + ".\n" +
			"Site: " + identity.StoreName + ".\nUnit: " + identity.UnitName + ".\nSerial: " + identity.Serial + ".\n" +
			"Address is a maintenance reference; confirm the current address with operations.\n" +
			"Controller management uses HTTP on port 8080. This support host runs no controller services.\n" +
			"The controller's /exports/maintenance.zip contains configuration, device and history CSVs.\n" +
			"Transfer account is kept in /root/.netrc for archive01.coldstore.internal.\n" +
			"Read and export copies before the approved change window; confirm alarms with operations.\n"})
	s.file(baitFile{Path: industrialRoot + "/README.txt", Owner: "root", Mode: 0o644, At: created,
		Text: "Refrigeration support archive\n\nInventory and communications are maintenance reference records.\n" +
			"The controller's own maintenance export contains its configuration and sampled history.\n"})
	user, password := refrigeration.MaintenanceCredential(refrigerationDeviceSeed(s.cfg))
	s.file(baitFile{Path: "/root/.netrc", Owner: "root", Mode: 0o600, At: created,
		Text: "machine archive01.coldstore.internal\n  login " + user + "\n  password " + password + "\n"})
	s.plant(refrigerationArchiveCanary(s.cfg))
	s.plan.Hosts = append(s.plan.Hosts,
		baitHost{Names: []string{"archive01", "archive01.coldstore.internal", s.db.IP}, IP: s.db.IP},
		baitHost{Names: []string{asset.ID, asset.ID + "." + s.domain, asset.Address}, IP: asset.Address})
	s.plan.Links = append(s.plan.Links, baitLink{Path: s.home + "/ot", Target: industrialRoot, At: exported})
	s.file(baitFile{Path: s.home + "/.bash_history", Owner: s.user, Mode: 0o600, At: 1,
		Offset: -300, InPlace: true, Text: "cd ~/ot\ncat inventory.json\ncat maintenance/handover.txt\nexit\n"})
	s.file(baitFile{Path: "/root/.bash_history", Owner: "root", Mode: 0o600, At: 1,
		Offset: -60, InPlace: true, Text: strings.Join([]string{"cd " + industrialRoot, "cat inventory.json", "cat exports/refrigeration01/communications.csv", "cat maintenance/handover.txt", "exit", ""}, "\n")})
}
