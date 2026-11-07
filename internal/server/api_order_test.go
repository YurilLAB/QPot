package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

// The web UI redraws a list when an answer differs from the one before (and
// loses keyboard focus in it), so a list the server builds from a map keeps
// one order: by name, or for counts, by count and then by name.

// runningDockerOnPath puts a stand-in docker on PATH that reports one running
// container to any command, so the instance counts as running.
func runningDockerOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	line := `{"Service":"cowrie","State":"running","Health":""}`
	name, body := "docker", "#!/bin/sh\necho '"+line+"'\n"
	if runtime.GOOS == "windows" {
		name, body = "docker.cmd", "@echo "+line+"\r\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { // #nosec G306 -- test helper; must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// orderDB answers GetEvents with fixed events (for /api/techniques).
type orderDB struct {
	fakeDB
	evs []*database.Event
}

func (o *orderDB) GetEvents(context.Context, database.EventFilter) ([]*database.Event, error) {
	return o.evs, nil
}

// orderCluster loads a cluster.json with several members into the server.
func orderCluster(t *testing.T, s *Server, names []string) {
	t.Helper()
	now := time.Now().UTC()
	nodes := map[string]*cluster.Node{}
	for i, n := range names {
		id := fmt.Sprintf("node-%02d", len(names)-i)
		nodes[id] = &cluster.Node{ID: id, Name: n, Address: "10.0.0.1", Port: 7946 + i, Status: cluster.NodeStatusHealthy, JoinedAt: now}
	}
	local := nodes["node-01"]
	data, err := json.Marshal(cluster.Cluster{ID: "cl-order", Name: "lab", PasswordHash: "x", CreatedAt: now, UpdatedAt: now,
		LocalNode: local, Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cluster.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cm := cluster.NewManager(dir)
	if c, err := cm.LoadCluster(); err != nil || c == nil {
		t.Fatalf("LoadCluster: %v", err)
	}
	s.cluster = cm
}

func TestListsKeepTheirOrder(t *testing.T) {
	runningDockerOnPath(t)
	a := newAPITestServer(t, "api-order", nil)
	mgr, err := instance.NewManager(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.s.manager = mgr
	a.runner.states = map[string]instance.ServiceState{}
	for _, n := range []string{"vector", "cowrie", "clickhouse", "dionaea", "adbhoney", "heralding", "endlessh"} {
		a.runner.states[n] = instance.ServiceState{State: "running"}
	}
	// Techniques: three with two events each, two with one.
	db := &orderDB{}
	for _, id := range []string{"T1110", "T1059", "T1078", "T1059", "T1110", "T1595", "T1078", "T1021"} {
		db.evs = append(db.evs, &database.Event{TechniqueID: id, TechniqueName: "n-" + id})
	}
	a.s.database = db
	orderCluster(t, a.s, []string{"sensor-c", "sensor-a", "sensor-e", "sensor-b", "sensor-d"})

	byName := func(names []string) []string {
		s := append([]string(nil), names...)
		sort.Strings(s)
		return s
	}
	lists := []struct {
		path string
		// names takes the list out of an answer.
		names func(t *testing.T, body []byte) []string
		// want is the order it must have.
		want func([]string) []string
	}{
		{"/api/status", func(t *testing.T, b []byte) []string {
			var v struct{ Honeypots []struct{ Name string } }
			mustDecode(t, b, &v)
			var out []string
			for _, h := range v.Honeypots {
				out = append(out, h.Name)
			}
			return out
		}, byName},
		{"/api/honeypots", func(t *testing.T, b []byte) []string {
			var v []struct{ Name string }
			mustDecode(t, b, &v)
			var out []string
			for _, h := range v {
				out = append(out, h.Name)
			}
			return out
		}, byName},
		{"/api/honeypots/settings", func(t *testing.T, b []byte) []string {
			var v struct{ Honeypots []struct{ Name string } }
			mustDecode(t, b, &v)
			var out []string
			for _, h := range v.Honeypots {
				out = append(out, h.Name)
			}
			return out
		}, byName},
		{"/api/instance#honeypots", func(t *testing.T, b []byte) []string {
			var v struct{ Honeypots []struct{ Name string } }
			mustDecode(t, b, &v)
			var out []string
			for _, h := range v.Honeypots {
				out = append(out, h.Name)
			}
			return out
		}, byName},
		{"/api/instance#services", func(t *testing.T, b []byte) []string {
			var v struct{ Services []struct{ Name string } }
			mustDecode(t, b, &v)
			var out []string
			for _, h := range v.Services {
				out = append(out, h.Name)
			}
			return out
		}, byName},
		{"/api/cluster", func(t *testing.T, b []byte) []string {
			var v struct{ Nodes []struct{ Name string } }
			mustDecode(t, b, &v)
			var out []string
			for _, h := range v.Nodes {
				out = append(out, h.Name)
			}
			return out
		}, byName},
		{"/api/techniques", func(t *testing.T, b []byte) []string {
			var v []struct {
				ID    string `json:"technique_id"`
				Count int    `json:"count"`
			}
			mustDecode(t, b, &v)
			var out []string
			for _, h := range v {
				out = append(out, fmt.Sprintf("%s:%d", h.ID, h.Count))
			}
			return out
		}, func([]string) []string { return []string{"T1059:2", "T1078:2", "T1110:2", "T1021:1", "T1595:1"} }},
	}
	for _, l := range lists {
		path, _, _ := strings.Cut(l.path, "#")
		var first []string
		for i := 0; i < 30; i++ {
			rec := a.do(http.MethodGet, path, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", l.path, rec.Code, rec.Body.String())
			}
			got := l.names(t, rec.Body.Bytes())
			if i == 0 {
				first = got
				if len(got) < 2 {
					t.Fatalf("%s: %d items, too few to show an order", l.path, len(got))
				}
				if want := l.want(got); !reflect.DeepEqual(got, want) {
					t.Errorf("%s: order %v, want %v", l.path, got, want)
				}
				continue
			}
			if !reflect.DeepEqual(got, first) {
				t.Errorf("%s: call %d gave %v after %v", l.path, i+1, got, first)
				break
			}
		}
	}
}

func mustDecode(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
}
