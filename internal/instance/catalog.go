package instance

import (
	"sort"

	"github.com/qpot/qpot/internal/config"
)

// honeypotDescriptions are the one-line descriptions `qpot honeypot list` and
// the web UI show.
var honeypotDescriptions = map[string]string{
	"cowrie": "SSH/Telnet medium-interaction shell", "dionaea": "Malware capture (SMB/FTP/MSSQL/SIP)",
	"conpot": "Industrial devices (PLC/RTU and other profiles)", "tanner": "Web application (multi-service)",
	"refrigeration": "AK-SM 800A refrigeration supervisor (virtual temperatures, defrost and alarms)",
	"adbhoney":      "Android Debug Bridge", "endlessh": "SSH tarpit",
	"heralding": "Credential catcher (12 protocols)", "honeyaml": "YAML-defined API honeypot",
	"elasticpot": "Elasticsearch", "ciscoasa": "Cisco ASA (CVE-2018-0101)",
	"citrixhoneypot": "Citrix NetScaler (CVE-2019-19781)", "ddospot": "UDP amplification (NTP/DNS/SSDP)",
	"ipphoney": "IPP / network printer", "mailoney": "SMTP",
	"medpot": "HL7 / medical", "redishoneypot": "Redis",
	"dicompot":  "DICOM (medical imaging)",
	"beelzebub": "LLM-backed SSH/HTTP (needs Ollama/API)", "galah": "LLM-backed web (needs Ollama/API)",
	"go-pot": "HTTP tarpit", "h0neytr4p": "Web exploit trap", "hellpot": "HTTP tarpit",
	"log4pot": "Log4Shell (CVE-2021-44228)", "miniprint": "Network printer (JetDirect)",
	"sentrypeer": "SIP / VoIP", "wordpot": "WordPress",
	"ssh-proxy": "High-interaction SSH (real OpenSSH behind the HiFi broker)",
}

// HoneypotDescription returns a honeypot's one-line description ("" for a
// name QPot does not ship).
func HoneypotDescription(name string) string { return honeypotDescriptions[name] }

// PortMapping is one port a honeypot publishes on the host.
type PortMapping struct {
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port"`
	Protocol      string `json:"protocol"` // "tcp" or "udp"
}

// HostPortMappings returns the host ports each enabled honeypot publishes, as
// the compose file assigns them (PublishedHostPorts), by honeypot. A
// honeypot whose port another service publishes (tanner's web front end) has
// none.
func HostPortMappings(cfg *config.Config) map[string][]PortMapping {
	assigned := PublishedHostPorts(cfg)
	out := map[string][]PortMapping{}
	for name, hp := range cfg.SnapshotHoneypots() {
		if !hp.Enabled || deployProfileFor(name).Internal {
			continue
		}
		tcp, udp := deployPorts(cfg, name)
		if len(tcp) == 0 && len(udp) == 0 {
			tcp = []int{hp.Port}
		}
		var ms []PortMapping
		for _, p := range tcp {
			if h, ok := assigned[portKey(name, p)]; ok {
				ms = append(ms, PortMapping{ContainerPort: p, HostPort: h, Protocol: "tcp"})
			}
		}
		for _, p := range udp {
			if h, ok := assigned[portKey(name, p)]; ok {
				ms = append(ms, PortMapping{ContainerPort: p, HostPort: h, Protocol: "udp"})
			}
		}
		sort.Slice(ms, func(i, j int) bool {
			if ms[i].ContainerPort != ms[j].ContainerPort {
				return ms[i].ContainerPort < ms[j].ContainerPort
			}
			return ms[i].Protocol < ms[j].Protocol
		})
		out[name] = ms
	}
	return out
}
