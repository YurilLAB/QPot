//go:build linux

package netguard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestNetguardKernelIsolation installs actual nftables rules only in a new
// network namespace. Unprivileged runs also create a user namespace. It never
// changes the host firewall or Docker.
func TestNetguardKernelIsolation(t *testing.T) {
	if os.Getenv("QPOT_TEST_NETGUARD") != "1" {
		t.Skip("set QPOT_TEST_NETGUARD=1 to exercise isolated Linux kernel rules")
	}
	role := os.Getenv("QPOT_NETGUARD_TEST_ROLE")
	if role == "controller" || role == "endpoint" {
		before := os.Getenv("QPOT_NETGUARD_TEST_PARENT_NS")
		now, err := os.Readlink("/proc/self/ns/net")
		if err != nil || before == "" || now == before {
			t.Fatalf("refusing to modify a namespace not isolated from parent: %q %v", now, err)
		}
		if role == "endpoint" {
			kernelEndpoint(t)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ip", "link", "add", "br-qpot-probe", "type", "bridge")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("create isolated bridge: %v: %s", err, out)
		}
		spec := Spec{Table: "qpot_kernel_probe", Ifaces: []string{"br-qpot-probe"}, Cells: []string{"br-qpot-probe"}, Mode: ModePrivate}
		if err := Apply(spec); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = Remove(spec.Table) })
		if err := Check(spec); err != nil {
			t.Fatal(err)
		}
		t.Log("actual nftables Apply and Check succeeded inside isolated user/network namespace")
		for _, ipv6 := range []bool{false, true} {
			name := "IPv4"
			if ipv6 {
				name = "IPv6"
			}
			t.Run(name, func(t *testing.T) { kernelPacketMatrix(t, ipv6) })
		}
		return
	}
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"--user", "--map-root-user", "--net"}
	if os.Getenv("QPOT_NETGUARD_ROOT_NAMESPACE") == "1" {
		if os.Geteuid() != 0 {
			t.Fatal("explicit root namespace mode requires root")
		}
		args = []string{"--net"}
	}
	args = append(args, os.Args[0], "-test.run=^TestNetguardKernelIsolation$", "-test.v")
	cmd := exec.CommandContext(ctx, "unshare", args...)
	cmd.Env = append(os.Environ(), "QPOT_NETGUARD_TEST_ROLE=controller", "QPOT_NETGUARD_TEST_PARENT_NS="+parent)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated netguard kernel probe failed: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

type kernelLink struct{ Name, Address string }
type kernelNodeConfig struct {
	Links   []kernelLink
	Gateway string
	ID      string
	HTTP    []string
	DNS     string
}
type kernelRequest struct{ Action, Address string }
type kernelResponse struct {
	OK    bool
	Error string
	Value string
	Count int64
}

func kernelIP(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("isolated ip %v: %v: %s", args, err, out)
	}
}

// Endpoint control is a local pipe, separate from the network under test.
func kernelEndpoint(t *testing.T) {
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Println("KERNEL_READY")
	decoder := json.NewDecoder(os.Stdin)
	var cfg kernelNodeConfig
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	kernelIP(t, "link", "set", "lo", "up")
	for _, link := range cfg.Links {
		args := []string{"address", "add", link.Address, "dev", link.Name}
		if strings.Contains(link.Address, ":") {
			args = append(args, "nodad")
		}
		kernelIP(t, args...)
		kernelIP(t, "link", "set", link.Name, "up")
	}
	if cfg.Gateway != "" {
		args := []string{"route", "add", "default", "via", cfg.Gateway}
		if strings.Contains(cfg.Gateway, ":") {
			args = append([]string{"-6"}, args...)
		}
		kernelIP(t, args...)
	}
	for _, address := range cfg.HTTP {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, cfg.ID) })}
		t.Cleanup(func() { _ = server.Close() })
		go func() { _ = server.Serve(listener) }()
	}
	var dnsCount atomic.Int64
	if cfg.DNS != "" {
		conn, err := net.ListenPacket("udp", cfg.DNS)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		go func() {
			packet := make([]byte, 512)
			for {
				n, peer, err := conn.ReadFrom(packet)
				if err != nil {
					return
				}
				dnsCount.Add(1)
				if n >= 12 {
					packet[2] |= 0x80
				}
				_, _ = conn.WriteTo(packet[:n], peer)
			}
		}()
	}
	write := func(response kernelResponse) {
		data, _ := json.Marshal(response)
		fmt.Printf("KERNEL_RESPONSE %s\n", data)
	}
	write(kernelResponse{OK: true})
	for {
		var request kernelRequest
		if err := decoder.Decode(&request); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatal(err)
		}
		response := kernelResponse{Count: dnsCount.Load()}
		switch request.Action {
		case "count":
			response.OK = true
		case "diagnostic":
			b, err := exec.Command("ip", "-6", "route", "show").CombinedOutput()
			response.Value = string(b)
			response.OK = err == nil
		case "http":
			client := &http.Client{Timeout: 600 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 400 * time.Millisecond}).DialContext}}
			res, err := client.Get("http://" + request.Address + "/")
			if err != nil {
				response.Error = err.Error()
			} else {
				b, err := io.ReadAll(io.LimitReader(res.Body, 1024))
				_ = res.Body.Close()
				response.Value = string(b)
				response.OK = err == nil && res.StatusCode == http.StatusOK
			}
		case "dns":
			conn, err := net.DialTimeout("udp", request.Address, 400*time.Millisecond)
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
				query := []byte{0x51, 0x50, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'p', 'r', 'o', 'b', 'e', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1}
				_, err = conn.Write(query)
				if err == nil {
					reply := make([]byte, 512)
					n, readErr := conn.Read(reply)
					err = readErr
					response.OK = err == nil && n >= 12 && reply[0] == 0x51 && reply[1] == 0x50 && reply[2]&0x80 != 0
				}
				_ = conn.Close()
			}
			if err != nil {
				response.Error = err.Error()
			}
		default:
			t.Fatalf("unexpected fixed fixture action %q", request.Action)
		}
		write(response)
	}
}

type kernelNode struct {
	cmd   *exec.Cmd
	input io.WriteCloser
	lines <-chan string
	done  <-chan error
}

func startKernelNode(t *testing.T, ctx context.Context) *kernelNode {
	t.Helper()
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "unshare", "--net", os.Args[0], "-test.run=^TestNetguardKernelIsolation$", "-test.v")
	cmd.Env = append(os.Environ(), "QPOT_NETGUARD_TEST_ROLE=endpoint", "QPOT_NETGUARD_TEST_PARENT_NS="+parent)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	node := &kernelNode{cmd: cmd, input: input, lines: lines, done: done}
	t.Cleanup(func() {
		_ = input.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	for {
		line := node.line(t)
		if line == "KERNEL_READY" {
			return node
		}
	}
}

func (n *kernelNode) line(t *testing.T) string {
	t.Helper()
	select {
	case line, ok := <-n.lines:
		if !ok {
			t.Fatal("isolated endpoint exited before response")
		}
		return line
	case <-time.After(4 * time.Second):
		t.Fatal("isolated endpoint control timed out")
		return ""
	}
}
func (n *kernelNode) send(t *testing.T, value any) kernelResponse {
	t.Helper()
	if err := json.NewEncoder(n.input).Encode(value); err != nil {
		t.Fatal(err)
	}
	for {
		line := n.line(t)
		if raw, ok := strings.CutPrefix(line, "KERNEL_RESPONSE "); ok {
			var response kernelResponse
			if err := json.Unmarshal([]byte(raw), &response); err != nil {
				t.Fatal(err)
			}
			return response
		}
	}
}

// Translate only the fixed lab fixtures to a corresponding ULA fixture.
func kernelAddress(t *testing.T, address string, ipv6 bool) string {
	t.Helper()
	if !ipv6 || address == "" {
		return address
	}
	host, prefix, hasPrefix := strings.Cut(address, "/")
	var port string
	if strings.Contains(host, ":") {
		var err error
		host, port, err = net.SplitHostPort(host)
		if err != nil {
			t.Fatal(err)
		}
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 || parts[0] != "198" || parts[1] != "18" {
		t.Fatalf("unexpected fixed fixture address %q", address)
	}
	host = "fd42:198:18:" + parts[2] + "::" + parts[3]
	if hasPrefix {
		if prefix != "24" {
			t.Fatal("unexpected lab prefix")
		}
		return host + "/64"
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func kernelPacketMatrix(t *testing.T, ipv6 bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	address := func(value string) string { return kernelAddress(t, value, ipv6) }
	if ipv6 {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/default/forwarding", []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, bridge := range []struct{ Name, Address string }{{"br-cell1", "198.18.11.1/24"}, {"br-cell2", "198.18.12.1/24"}, {"br-ingress", "198.18.13.1/24"}} {
		kernelIP(t, "link", "add", bridge.Name, "type", "bridge")
		t.Cleanup(func() { kernelIP(t, "link", "delete", bridge.Name) })
		args := []string{"address", "add", address(bridge.Address), "dev", bridge.Name}
		if ipv6 {
			args = append(args, "nodad")
		}
		kernelIP(t, args...)
		kernelIP(t, "link", "set", bridge.Name, "up")
	}
	kernelIP(t, "link", "set", "lo", "up")
	// This namespaced sysctl cannot alter the parent host's forwarding policy.
	forwarding := "/proc/sys/net/ipv4/ip_forward"
	if ipv6 {
		forwarding = "/proc/sys/net/ipv6/conf/all/forwarding"
	}
	if err := os.WriteFile(forwarding, []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	index := 0
	attach := func(node *kernelNode, bridge string) string {
		index++
		host := fmt.Sprintf("v%d", index)
		peer := fmt.Sprintf("p%d", index)
		kernelIP(t, "link", "add", host, "type", "veth", "peer", "name", peer)
		kernelIP(t, "link", "set", host, "master", bridge)
		kernelIP(t, "link", "set", host, "up")
		kernelIP(t, "link", "set", peer, "netns", strconv.Itoa(node.cmd.Process.Pid))
		return peer
	}
	type port struct{ bridge, address string }
	makeNode := func(id, gateway string, ports []port, httpAddresses []string, dns string) *kernelNode {
		node := startKernelNode(t, ctx)
		cfg := kernelNodeConfig{ID: id, Gateway: address(gateway), DNS: address(dns)}
		for _, httpAddress := range httpAddresses {
			cfg.HTTP = append(cfg.HTTP, address(httpAddress))
		}
		for _, p := range ports {
			cfg.Links = append(cfg.Links, kernelLink{Name: attach(node, p.bridge), Address: address(p.address)})
		}
		if response := node.send(t, cfg); !response.OK {
			t.Fatalf("configure%s: %+v", id, response)
		}
		return node
	}
	cell1 := makeNode("cell1", "198.18.11.1", []port{{"br-cell1", "198.18.11.10/24"}}, []string{"198.18.11.10:19080"}, "")
	makeNode("peer1", "198.18.11.1", []port{{"br-cell1", "198.18.11.20/24"}}, []string{"198.18.11.20:19080"}, "")
	cell2 := makeNode("cell2", "198.18.12.1", []port{{"br-cell2", "198.18.12.10/24"}}, []string{"198.18.12.10:19080"}, "")
	makeNode("broker", "198.18.13.1", []port{{"br-cell1", "198.18.11.254/24"}, {"br-cell2", "198.18.12.254/24"}, {"br-ingress", "198.18.13.10/24"}}, []string{"198.18.13.10:19080"}, "")
	ingress := makeNode("ingress", "198.18.13.1", []port{{"br-ingress", "198.18.13.20/24"}}, []string{"198.18.13.20:19080"}, "198.18.13.20:53")
	listener, err := net.Listen("tcp", address("198.18.11.1:19080"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "labhost") })}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	assertHTTP := func(label string, node *kernelNode, target, wantID string, allowed bool) {
		t.Helper()
		response := node.send(t, kernelRequest{Action: "http", Address: address(target)})
		if response.OK != allowed || (allowed && response.Value != wantID) {
			if ipv6 {
				b, _ := exec.Command("ip", "-6", "route", "show").CombinedOutput()
				t.Logf("router routes: %s", b)
				b, _ = exec.Command("ip", "-6", "neigh", "show").CombinedOutput()
				t.Logf("router neighbors: %s", b)
				t.Logf("endpoint routes: %s", node.send(t, kernelRequest{Action: "diagnostic"}).Value)
			}
			t.Fatalf("%s: want allowed=%v id=%s, got%+v", label, allowed, wantID, response)
		}
		t.Logf("%s allowed=%v", label, allowed)
	}
	for _, target := range []struct{ address, id string }{{"198.18.11.20:19080", "peer1"}, {"198.18.11.1:19080", "labhost"}, {"198.18.12.10:19080", "cell2"}, {"198.18.13.10:19080", "broker"}, {"198.18.13.20:19080", "ingress"}} {
		assertHTTP("before guard: "+target.id, cell1, target.address, target.id, true)
	}
	assertHTTP("before guard: inbound", ingress, "198.18.11.10:19080", "cell1", true)
	assertHTTP("broker has no private-interface listener", cell1, "198.18.11.254:19080", "", false)
	if response := cell1.send(t, kernelRequest{Action: "dns", Address: address("198.18.13.20:53")}); !response.OK {
		t.Fatalf("owned DNS spy was not reachable before guard: %+v", response)
	}
	dnsBefore := ingress.send(t, kernelRequest{Action: "count"}).Count
	if dnsBefore != 1 {
		t.Fatalf("owned DNS spy did not receive baseline packet: %d", dnsBefore)
	}
	spec := Spec{Table: "qpot_kernel_cells", Ifaces: []string{"br-cell1", "br-cell2"}, Cells: []string{"br-cell1", "br-cell2"}, Mode: ModePrivate}
	t.Cleanup(func() { _ = Remove(spec.Table) })
	for _, mode := range []Mode{ModePrivate, ModeAll} {
		spec.Mode = mode
		t.Logf("actual kernel cell policy in mode=%s", mode)
		if err := Apply(spec); err != nil {
			t.Fatal(err)
		}
		if err := Check(spec); err != nil {
			t.Fatal(err)
		}
		assertHTTP("same-cell peer", cell1, "198.18.11.20:19080", "peer1", true)
		assertHTTP("host gateway", cell1, "198.18.11.1:19080", "", false)
		assertHTTP("cross-cell", cell1, "198.18.12.10:19080", "", false)
		assertHTTP("cross-cell reverse", cell2, "198.18.11.10:19080", "", false)
		assertHTTP("broker public-interface reentry", cell1, "198.18.13.10:19080", "", false)
		assertHTTP("off-cell target", cell1, "198.18.13.20:19080", "", false)
		assertHTTP("broker private-interface remains unbound", cell1, "198.18.11.254:19080", "", false)
		assertHTTP("incoming flow and established response", ingress, "198.18.11.10:19080", "cell1", true)
		if response := cell1.send(t, kernelRequest{Action: "dns", Address: address("198.18.13.20:53")}); response.OK {
			t.Fatal("private cell reached off-cell DNS")
		}
		if count := ingress.send(t, kernelRequest{Action: "count"}).Count; count != dnsBefore {
			t.Fatalf("blocked DNS leaked a packet to owned spy: count%d→%d", dnsBefore, count)
		}
	}
	if err := Remove(spec.Table); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ address, id string }{{"198.18.11.1:19080", "labhost"}, {"198.18.12.10:19080", "cell2"}, {"198.18.13.10:19080", "broker"}, {"198.18.13.20:19080", "ingress"}} {
		assertHTTP("after remove: "+target.id, cell1, target.address, target.id, true)
	}
	if response := cell1.send(t, kernelRequest{Action: "dns", Address: address("198.18.13.20:53")}); !response.OK {
		t.Fatalf("DNS target did not recover after rule removal: %+v", response)
	}
	t.Log("actual isolated kernel packet matrix passed; all blocked targets answered before guard and after removal")
}
