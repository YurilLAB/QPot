package main

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// portPair is one published honeypot port.
type portPair struct{ Container, Host int }

// honeypotPorts lists a honeypot's published ports.
type honeypotPorts struct {
	Name  string
	Risk  string
	Ports []portPair
}

// setupSummary is what the owner needs once setup is done: where the web
// UI is, how to log in, what runs where and what to do next.
type setupSummary struct {
	Instance  string
	Started   bool   // containers and control plane were started
	Healthy   bool   // every health check passed
	Service   string // the systemd unit, when installed as a service
	Bind      string
	Port      int
	ShowID    bool // print the QPot ID (only on the owner's own terminal)
	QPotID    string
	SSHTarget string // user@host for the tunnel example
	Honeypots []honeypotPorts
	Config    string
	DataPath  string
	ServeLog  string
	SetupLog  string
	Sandbox   string
}

// webURLs returns the addresses to open: the local one, and the network one
// when the web UI listens beyond this computer.
func (s setupSummary) webURLs() (local, remote string) {
	port := strconv.Itoa(s.Port)
	switch s.Bind {
	case "0.0.0.0", "::", "":
		local = "http://" + net.JoinHostPort("127.0.0.1", port) + "/"
		if ip := getLocalIP(); ip != "" && ip != "127.0.0.1" {
			remote = "http://" + net.JoinHostPort(ip, port) + "/"
		}
	default:
		local = "http://" + net.JoinHostPort(s.Bind, port) + "/"
	}
	return local, remote
}

func (s setupSummary) loopback() bool {
	return s.Bind == "127.0.0.1" || s.Bind == "::1" || strings.HasPrefix(s.Bind, "127.")
}

// iflag is the instance flag to show in commands ("" for the default one).
func (s setupSummary) iflag() string {
	if s.Instance == "default" || s.Instance == "" {
		return ""
	}
	return " -i " + s.Instance
}

// renderSummary prints the end-of-setup summary. Every value that comes
// from the system or a config file goes through termSafe.
func renderSummary(w io.Writer, s setupSummary) {
	t := termSafe
	i := t(s.iflag())
	local, remote := s.webURLs()
	line := strings.Repeat("=", 64)
	fmt.Fprintln(w)
	fmt.Fprintln(w, line)
	switch {
	case !s.Started:
		fmt.Fprintf(w, " QPot instance %q is set up (not started yet)\n", t(s.Instance))
	case s.Healthy:
		fmt.Fprintf(w, " QPot is running: instance %q\n", t(s.Instance))
	default:
		fmt.Fprintf(w, " QPot is started, but some checks failed: instance %q\n", t(s.Instance))
	}
	fmt.Fprintln(w, line)

	fmt.Fprintln(w, "\nWeb UI")
	fmt.Fprintf(w, "  Open:        %s\n", t(local))
	if remote != "" {
		fmt.Fprintf(w, "  On your network: %s\n", t(remote))
	}
	if s.ShowID && s.QPotID != "" {
		fmt.Fprintf(w, "  Log in with your QPot ID: %s\n", t(s.QPotID))
		fmt.Fprintln(w, "  Keep the ID private: it is the password for the web UI and API.")
		fmt.Fprintf(w, "  Show it again any time with: qpot id%s\n", i)
	} else {
		fmt.Fprintf(w, "  Log in with your QPot ID. Show it with: qpot id%s\n", i)
	}
	if s.loopback() {
		target := s.SSHTarget
		if target == "" {
			target = "<user>@<this-computer>"
		}
		fmt.Fprintln(w, "  The web UI only listens on this computer. To open it from another")
		fmt.Fprintln(w, "  computer, run this there and then open the address above in its browser:")
		fmt.Fprintf(w, "    ssh -N -L %d:%s:%d %s\n", s.Port, t(s.Bind), s.Port, t(target))
	} else {
		fmt.Fprintln(w, "  The web UI is reachable from the network over plain HTTP. Allow only")
		fmt.Fprintln(w, "  trusted addresses to it in your firewall, or bind it to 127.0.0.1 again")
		fmt.Fprintf(w, "  (web_ui.bind_addr in qpot config%s) and use an SSH tunnel.\n", i)
	}

	fmt.Fprintln(w, "\nHoneypots (attackers connect to these ports on this computer)")
	if len(s.Honeypots) == 0 {
		fmt.Fprintln(w, "  none enabled")
	}
	for _, h := range s.Honeypots {
		var ports []string
		for _, p := range h.Ports {
			ports = append(ports, fmt.Sprintf("%d (as %d)", p.Host, p.Container))
		}
		risk := ""
		if h.Risk != "" {
			risk = " [" + t(h.Risk) + " risk]"
		}
		fmt.Fprintf(w, "  %-15s%s %s\n", t(h.Name), risk, t(strings.Join(ports, ", ")))
	}
	fmt.Fprintln(w, "  To expose a honeypot to the internet, forward the port your router or")
	fmt.Fprintln(w, "  firewall receives (for example 22) to the port shown here.")
	if s.Sandbox != "" {
		fmt.Fprintf(w, "  Isolation: %s\n", t(s.Sandbox))
	}

	fmt.Fprintln(w, "\nFiles")
	fmt.Fprintf(w, "  Settings:    %s\n", t(s.Config))
	fmt.Fprintf(w, "  Data:        %s\n", t(s.DataPath))
	if s.ServeLog != "" {
		fmt.Fprintf(w, "  Web UI log:  %s\n", t(s.ServeLog))
	}
	if s.SetupLog != "" {
		fmt.Fprintf(w, "  Setup log:   %s\n", t(s.SetupLog))
	}
	if s.Service != "" {
		fmt.Fprintf(w, "  Service:     %s (starts at boot)\n", t(s.Service))
	}

	fmt.Fprintln(w, "\nNext steps")
	if !s.Started {
		fmt.Fprintf(w, "  qpot up -d%-16s start the honeypots and the web UI\n", i)
	}
	fmt.Fprintf(w, "  qpot status%-15s what is running\n", i)
	fmt.Fprintf(w, "  qpot logs%-17s honeypot logs (add -f to follow, or a honeypot name)\n", i)
	fmt.Fprintf(w, "  qpot doctor%-15s check everything is healthy\n", i)
	fmt.Fprintf(w, "  qpot down%-17s stop QPot;  qpot up -d%s  starts it again\n", i, i)
	fmt.Fprintf(w, "  qpot config%-15s change settings (then: qpot down%s && qpot up -d%s)\n", i, i, i)
	fmt.Fprintf(w, "  qpot honeypot list%-8s all honeypots; add one with: qpot honeypot enable <name>%s\n", i, i)
	fmt.Fprintln(w, "  qpot doctor --explain <code>  explains an error code such as QP-PORT-001")
	fmt.Fprintln(w)
}

// summaryHoneypots lists the enabled honeypots with their published ports,
// as the compose generator assigns them.
func summaryHoneypots(cfg *config.Config) []honeypotPorts {
	byHP := map[string][]portPair{}
	for key, host := range instance.PublishedHostPorts(cfg) {
		name, cport, ok := strings.Cut(key, "\x00")
		if !ok {
			continue
		}
		c, err := strconv.Atoi(cport)
		if err != nil {
			continue
		}
		byHP[name] = append(byHP[name], portPair{Container: c, Host: host})
	}
	var out []honeypotPorts
	for _, name := range cfg.GetEnabledHoneypots() {
		ports := byHP[name]
		sort.Slice(ports, func(a, b int) bool { return ports[a].Container < ports[b].Container })
		hp, _ := cfg.GetHoneypotConfig(name)
		out = append(out, honeypotPorts{Name: name, Risk: hp.RiskLevel, Ports: ports})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}
