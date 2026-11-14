// Command cowrie_hunt_client runs its arguments as commands over one SSH
// connection to the local service, each on a channel of its own as `ssh host
// command` does, and prints what each answered with the fingerprint of the
// host key the service presented. With --shell as its first argument the
// commands are typed at a login shell on a terminal instead, and the one
// answer is everything the terminal showed (the image as shipped ends the
// connection with the first command it is given without a shell). It runs
// only inside the test container's network-none namespace.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// screen is what the terminal showed, written by the session and read while it runs.
type screen struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type answer struct {
	Out    string `json:"out"`
	Status int    `json:"status"`
}

func main() {
	var hostKey string
	config := &ssh.ClientConfig{
		User: "root", Auth: []ssh.AuthMethod{ssh.Password("local-test-only")}, Timeout: 5 * time.Second,
		// the host key the persona's own OpenSSH would show first
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		HostKeyCallback: func(_ string, remote net.Addr, key ssh.PublicKey) error {
			host, _, err := net.SplitHostPort(remote.String())
			if err != nil || !net.ParseIP(host).IsLoopback() {
				return fmt.Errorf("test SSH endpoint must be loopback")
			}
			hostKey = ssh.FingerprintSHA256(key)
			return nil
		},
	}
	connect := func() *ssh.Client {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", "127.0.0.1:22")
		must(err)
		must(conn.SetDeadline(time.Now().Add(100 * time.Second)))
		c, channels, requests, err := ssh.NewClientConn(conn, "127.0.0.1:22", config)
		must(err)
		return ssh.NewClient(c, channels, requests)
	}
	commands := os.Args[1:]
	client := connect()
	defer func() { _ = client.Close() }()

	if len(commands) > 0 && commands[0] == "--shell" {
		session, err := client.NewSession()
		must(err)
		must(session.RequestPty("xterm", 50, 200, ssh.TerminalModes{}))
		shown := &screen{}
		session.Stdout, session.Stderr = shown, shown
		stdin, err := session.StdinPipe()
		must(err)
		must(session.Shell())
		// a command is typed once the prompt stands, and the next one once it stands again: the
		// service takes its time to start a shell, and what is typed before that is lost
		prompt := func(from int, limit time.Duration) bool {
			for end := time.Now().Add(limit); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
				if text := shown.String(); len(text) > from && strings.Contains(text[from:], "# ") {
					return true
				}
			}
			return false
		}
		ready := prompt(0, 30*time.Second)
		for _, command := range commands[1:] {
			from := len(shown.String())
			_, err := io.WriteString(stdin, command+"\n")
			must(err)
			prompt(from, 20*time.Second)
		}
		_, _ = io.WriteString(stdin, "exit\n")
		done := make(chan error, 1)
		go func() { done <- session.Wait() }()
		ended := "no end within 15 s"
		select {
		case err := <-done:
			ended = fmt.Sprint(err)
		case <-time.After(15 * time.Second):
		}
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"host_key": hostKey, "prompt": ready, "ended": ended,
			"answers": []answer{{Out: strings.ReplaceAll(shown.String(), "\r\n", "\n")}}}))
		return
	}

	answers := make([]answer, 0, len(commands))
	for _, command := range commands {
		session, err := client.NewSession()
		must(err)
		out, err := session.CombinedOutput(command)
		status := 0
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			status = exit.ExitStatus()
		} else if err != nil {
			must(fmt.Errorf("%q: %w", command, err))
		}
		_ = session.Close()
		answers = append(answers, answer{Out: string(out), Status: status})
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"host_key": hostKey, "answers": answers}))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
