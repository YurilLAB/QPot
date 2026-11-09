package sshbackend

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

const contextDirectory = "/run/audit-context"

// ConnectionContext is trusted cell ownership written by the TCP broker before
// dialing. Generation is retained for correlation; the recorder does not have
// an independent lease generation against which to compare this read-only file.
type ConnectionContext struct {
	SessionID  string  `json:"session_id"`
	SrcIP      string  `json:"src_ip"`
	SrcPort    int     `json:"src_port"`
	StartedAt  string  `json:"started_at"`
	Generation *uint64 `json:"generation"`
}

func readContext(dir string) (ConnectionContext, error) {
	var context ConnectionContext
	name := filepath.Join(dir, "connection.json")
	info, err := os.Lstat(name)
	if err != nil {
		return context, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<10 {
		return context, errors.New("invalid connection context file")
	}
	f, err := os.Open(name)
	if err != nil {
		return context, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if err != nil {
		return context, err
	}
	if len(data) > 16<<10 {
		return context, errors.New("connection context is too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&context); err != nil {
		return context, fmt.Errorf("decode connection context: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return context, errors.New("connection context has trailing data")
	}
	id, err := hex.DecodeString(context.SessionID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != context.SessionID || net.ParseIP(context.SrcIP) == nil || context.SrcPort < 1 || context.SrcPort > 65535 || context.Generation == nil {
		return context, errors.New("invalid connection context fields")
	}
	if _, err := time.Parse(time.RFC3339Nano, context.StartedAt); err != nil {
		return context, errors.New("invalid connection context time")
	}
	return context, nil
}

func attribute(event *SessionEvent, dir string) {
	event.PeerIP = event.SrcIP
	event.PeerPort = event.SrcPort
	event.Attribution = "peer-only"
	context, err := readContext(dir)
	if err != nil {
		if _, dirErr := os.Stat(dir); dirErr == nil {
			event.Attribution = "context-unavailable"
			event.AttributionError = "trusted connection context unavailable or invalid"
		}
		return
	}
	event.SrcIP = context.SrcIP
	event.SrcPort = context.SrcPort
	event.SessionID = context.SessionID
	event.Generation = context.Generation
	event.Attribution = "broker-cell"
}
