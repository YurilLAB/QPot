package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/intelligence"
)

// batchDB serves a batch of captured events once, as the database serves
// unclassified rows to the intelligence worker, and records what is inserted.
type batchDB struct {
	fakeDB
	mu     sync.Mutex
	events []*database.Event
}

func (b *batchDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.events
	b.events = nil
	return out, nil
}

// plantedCfg returns an instance whose Cowrie persona carries every kind of
// planted canary (an AWS key, a dump), searching instance IDs in order.
func plantedCfg(t *testing.T) (*config.Config, []*canary.Canary) {
	t.Helper()
	for i := 0; i < 300; i++ {
		cfg := config.Default("planted")
		cfg.QPotID = fmt.Sprintf("qp_planted%018d", i)
		cfg.DataPath = t.TempDir()
		cfg.Canary.Enabled = true
		hp := cfg.Honeypots["cowrie"]
		hp.Enabled = true
		hp.CustomConfig = map[string]string{"persona": "ubuntu-noble"}
		cfg.Honeypots["cowrie"] = hp
		planted := instance.PlantedCanaries(cfg)
		kinds := map[canary.Kind]int{}
		for _, c := range planted {
			kinds[c.Kind]++
		}
		if kinds[canary.KindAWS] == 1 && kinds[canary.KindSSHKey] == 1 && kinds[canary.KindWeb] == 1 && kinds[canary.KindCredential] >= 4 {
			return cfg, planted
		}
	}
	t.Fatal("no instance plants every kind")
	return nil, nil
}

// TestPlantedCanariesTripEndToEnd: the server registers the canaries its
// Cowrie persona carries, and each trips from the event a captured session
// makes when the attacker uses it (as the collector maps cowrie's and
// heralding's log lines): the stolen key offered in a login, the user's
// password in a login, the database password and the tokens typed in
// commands, the AWS key the emulated CLI signed with, the SMTP password tried
// on heralding, and where the instance has them the chat webhook posted to
// from the honeypot, the monitoring login and the file server password tried
// elsewhere. Near misses trip nothing.
func TestPlantedCanariesTripEndToEnd(t *testing.T) {
	cfg, planted := plantedCfg(t)
	cs, err := canary.NewStore(cfg.DataPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SyncPlanted(instance.PlantedCanaries(cfg)); err != nil {
		t.Fatal(err)
	}
	if !cs.HasWatchValues() || len(cs.List()) != len(planted) {
		t.Fatalf("store holds %d canaries, %d planted", len(cs.List()), len(planted))
	}
	byName := map[string]*canary.Canary{}
	var creds []*canary.Canary
	for _, c := range planted {
		byName[c.Name] = c
		if c.Kind == canary.KindCredential {
			creds = append(creds, c)
		}
	}
	find := func(prefix string) *canary.Canary {
		for name, c := range byName {
			if strings.HasPrefix(name, prefix) {
				return c
			}
		}
		t.Fatalf("no canary %q", prefix)
		return nil
	}
	key, aws, ping := find("cowrie bait: root SSH key"), find("cowrie bait: AWS"), find("cowrie bait: backup healthcheck")
	user, smtp := find("cowrie bait: ubuntu password"), find("cowrie bait: SMTP password")
	dbPass := creds[0]
	for _, c := range creds {
		if strings.HasSuffix(c.Name, "database password") {
			dbPass = c
		}
	}
	now := time.Now().UTC()
	ev := func(ip, hp, et string, mod func(e *database.Event)) *database.Event {
		e := &database.Event{Timestamp: now, Honeypot: hp, SourceIP: ip, EventType: et, Protocol: "ssh",
			Metadata: map[string]string{"session": "s-" + ip}}
		mod(e)
		return e
	}
	events := []*database.Event{
		ev("203.0.113.1", "cowrie", "cowrie.client.fingerprint", func(e *database.Event) {
			e.Username = "root"
			e.Metadata["fingerprint"] = key.Values[1]
			e.Metadata["key"] = "ssh-ed25519 " + key.Values[0]
		}),
		ev("203.0.113.2", "cowrie", "cowrie.login.success", func(e *database.Event) {
			e.Username, e.Password = "ubuntu", user.Values[0]
		}),
		ev("203.0.113.3", "cowrie", "cowrie.command.input", func(e *database.Event) {
			e.Command = "mysql -h 10.0.0.9 -u backup -p'" + dbPass.Values[0] + "' -e 'show databases'"
		}),
		ev("203.0.113.4", "cowrie", "cowrie.credentials.use", func(e *database.Event) {
			e.Username, e.Password, e.Command = aws.AccessKeyID, aws.SecretAccessKey, "aws sts get-caller-identity"
		}),
		ev("203.0.113.5", "cowrie", "cowrie.command.input", func(e *database.Event) {
			e.Command = "curl -s http://10.1.1.1:8000/ping/" + ping.Token
		}),
		ev("203.0.113.6", "heralding", "heralding.login.failed", func(e *database.Event) {
			e.Protocol, e.Username, e.Password = "smtp", "crm@corp.internal", smtp.Values[0]
		}),
		// near misses: a brute-forced login, the key's type alone, a value cut short
		ev("198.51.100.1", "cowrie", "cowrie.login.failed", func(e *database.Event) { e.Username, e.Password = "root", "123456" }),
		ev("198.51.100.2", "cowrie", "cowrie.client.fingerprint", func(e *database.Event) {
			e.Metadata["key"] = "ssh-ed25519 " + key.Values[0][:40]
		}),
		ev("198.51.100.3", "cowrie", "cowrie.command.input", func(e *database.Event) {
			e.Command = "echo " + dbPass.Values[0][:len(dbPass.Values[0])-1]
		}),
	}
	git := find("cowrie bait: GitLab token")
	events = append(events, ev("203.0.113.7", "cowrie", "cowrie.command.input", func(e *database.Event) {
		e.Command = "git clone https://anna:" + git.Values[0] + "@git.corp.internal/ops/infra.git"
	}))
	// the files some instances carry beside those: each trips where its value is used
	more := map[*canary.Canary]string{}
	for _, c := range planted {
		ip := fmt.Sprintf("203.0.113.%d", 20+len(more))
		switch {
		case c.Name == "cowrie bait: ops chat webhook":
			events = append(events, ev(ip, "cowrie", "cowrie.command.input", func(e *database.Event) {
				e.Command = "curl -s -d '{\"text\":\"hi\"}' https://chat.corp.internal/hooks/" + c.Values[0]
			}))
		case strings.HasSuffix(c.Name, " login"): // the monitoring console's, from the admin's notes
			events = append(events, ev(ip, "heralding", "heralding.login.failed", func(e *database.Event) {
				e.Protocol, e.Username, e.Password = "http", "admin", c.Values[0]
			}))
		case c.Name == "cowrie bait: file server password":
			events = append(events, ev(ip, "heralding", "heralding.login.failed", func(e *database.Event) {
				e.Protocol, e.Username, e.Password = "ftp", "deploy", c.Values[0]
			}))
		default:
			continue
		}
		more[c] = ip
	}
	db := &batchDB{events: events}
	s := &Server{config: cfg, canaries: cs, database: db}
	cl := intelligence.NewClassifier(intelligence.NewATTCKLoader(t.TempDir()), nil)
	w := intelligence.NewWorker(cl, db, time.Hour, 100).WithCanaryMatcher(&canaryMatcher{s: s})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	tripped := map[string]string{}
	for _, e := range db.insertedEvents() {
		if e.Honeypot != "canary" || e.EventType != "canary_trip" || e.Metadata["severity"] != "critical" {
			continue
		}
		if prev, dup := tripped[e.Metadata["canary_id"]]; dup {
			t.Errorf("canary %s tripped twice (%s, %s)", e.Metadata["canary_id"], prev, e.SourceIP)
		}
		tripped[e.Metadata["canary_id"]] = e.SourceIP
	}
	want := map[*canary.Canary]string{key: "203.0.113.1", user: "203.0.113.2", dbPass: "203.0.113.3",
		aws: "203.0.113.4", ping: "203.0.113.5", smtp: "203.0.113.6", git: "203.0.113.7"}
	for c, ip := range more {
		want[c] = ip
	}
	for c, ip := range want {
		if tripped[c.ID] != ip {
			t.Errorf("%s (%s): tripped by %q, want %s", c.Name, c.Kind, tripped[c.ID], ip)
		}
	}
	for id, ip := range tripped {
		if strings.HasPrefix(ip, "198.51.100.") {
			t.Errorf("near miss from %s tripped %s", ip, id)
		}
	}
	if len(tripped) != len(planted) {
		t.Errorf("%d of %d planted canaries tripped", len(tripped), len(planted))
	}
}

// TestPlantedCanariesInAPI: the API lists the planted canaries with what they
// watch, refuses to delete them (QPot plants them again) and mints none of
// their kinds for an operator.
func TestPlantedCanariesInAPI(t *testing.T) {
	_, planted := plantedCfg(t)
	s := newCanaryTestServer(t, &fakeDB{})
	if err := s.canaries.SyncPlanted(planted); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/canaries", ""))
	var list struct {
		Canaries []map[string]any `json:"canaries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Canaries) != len(planted) {
		t.Fatalf("list: %v, %d entries", err, len(list.Canaries))
	}
	for _, c := range list.Canaries {
		if c["planted"] != true {
			t.Errorf("%v not marked planted", c["name"])
		}
		switch c["kind"] {
		case "credential":
			if v, _ := c["values"].([]any); len(v) == 0 {
				t.Errorf("%v without its values", c["name"])
			}
		case "ssh-key":
			if pk, _ := c["public_key"].(string); !strings.HasPrefix(pk, "ssh-ed25519 ") {
				t.Errorf("ssh key canary without its public key: %v", c["public_key"])
			}
		}
	}
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodDelete, "/api/canaries?id="+planted[0].ID, ""))
	if rec.Code != http.StatusConflict {
		t.Errorf("DELETE of a planted canary: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := s.canaries.Get(planted[0].ID); !ok {
		t.Error("planted canary deleted")
	}
	// the healthcheck URL also trips on the http channel, at the beacon
	for _, c := range planted {
		if c.Kind != canary.KindWeb {
			continue
		}
		rec = httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/c/"+c.Token, nil))
		trips := s.canaries.Trips(10)
		if len(trips) != 1 || trips[0].CanaryID != c.ID || trips[0].Channel != "http" {
			t.Errorf("beacon GET of the planted healthcheck: trips %+v", trips)
		}
	}
	for _, kind := range []string{"credential", "ssh-key"} {
		rec = httptest.NewRecorder()
		s.mux.ServeHTTP(rec, authReq(http.MethodPost, "/api/canaries", `{"kind":"`+kind+`","name":"x"}`))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST kind %s: %d", kind, rec.Code)
		}
	}
	if err := s.canaries.SyncPlanted(nil); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/canaries", ""))
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Canaries) != len(planted) {
		t.Fatalf("historical list: %v, %d entries", err, len(list.Canaries))
	}
	for _, c := range list.Canaries {
		if c["planted"] != true || c["historical"] != true {
			t.Fatalf("previous watch missing history/provenance flags: %v", c)
		}
	}
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodDelete, "/api/canaries?id="+planted[0].ID, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE historical canary: %d %s", rec.Code, rec.Body.String())
	}
	if _, exists := s.canaries.Get(planted[0].ID); exists {
		t.Fatal("API did not delete historical watch")
	}
}

// TestServerSyncsPlantedCanaries: a server started for an instance registers
// its planted canaries in the store from the start.
func TestServerSyncsPlantedCanaries(t *testing.T) {
	cfg, planted := plantedCfg(t)
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = 1 // nothing listens: the server comes up without a database
	cfg.Intelligence.Enabled = false
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.canaries == nil {
		t.Fatal("no canary store")
	}
	for _, c := range planted {
		if got, ok := s.canaries.Get(c.ID); !ok || !got.Planted {
			t.Errorf("%s not registered", c.Name)
		}
	}
}

// TestServerFollowsPlantedCanaries: the CLI changes what Cowrie plants while
// the server runs on (qpot honeypot enable cowrie, set cowrie bait=off or
// persona=..., a canary.base_url change, each saving the config file and
// recreating Cowrie): desired values are active, and earlier watches remain
// historical for copied values or old processes after a failed recreation.
func TestServerFollowsPlantedCanaries(t *testing.T) {
	old := plantedRecheck
	plantedRecheck = 0
	defer func() { plantedRecheck = old }()
	want, planted := plantedCfg(t)
	dir := t.TempDir()
	// the CLI's copy of the instance config: its own object, saved to the file
	cli := func(mod func(hp *config.HoneypotConfig, cfg *config.Config)) {
		t.Helper()
		cfg := config.Default("plantedfollow")
		cfg.QPotID, cfg.DataPath, cfg.ConfigPath = want.QPotID, dir, filepath.Join(dir, "config.yaml")
		cfg.Canary.Enabled = true
		hp := cfg.Honeypots["cowrie"]
		hp.CustomConfig = map[string]string{"persona": "ubuntu-noble"}
		mod(&hp, cfg)
		cfg.Honeypots["cowrie"] = hp
		if err := config.Save(cfg); err != nil {
			t.Fatal(err)
		}
	}
	cli(func(hp *config.HoneypotConfig, _ *config.Config) { hp.Enabled = false })
	srvCfg, err := config.Parse(mustRead(t, filepath.Join(dir, "config.yaml")), filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	srvCfg.QPotID = want.QPotID
	srvCfg.Database.Host, srvCfg.Database.Port = "127.0.0.1", 1
	srvCfg.Intelligence.Enabled = false
	s, err := New(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.canaries.List()); n != 0 {
		t.Fatalf("cowrie off: %d canaries", n)
	}
	var dbPass, aws *canary.Canary
	for _, c := range planted {
		if strings.HasSuffix(c.Name, "database password") {
			dbPass = c
		}
		if c.Kind == canary.KindAWS {
			aws = c
		}
	}
	m := &canaryMatcher{s: s}
	use := func(ip, cmd string) bool {
		return m.MatchEvent(context.Background(), &database.Event{Timestamp: time.Now().UTC(), Honeypot: "cowrie",
			SourceIP: ip, EventType: "cowrie.command.input", Command: cmd})
	}

	// qpot honeypot enable cowrie
	cli(func(hp *config.HoneypotConfig, _ *config.Config) { hp.Enabled = true })
	if !use("203.0.113.10", "mysql -u backup -p'"+dbPass.Values[0]+"'") {
		t.Error("cowrie enabled while the server runs: its database password does not trip")
	}
	if got, ok := s.canaries.Get(aws.ID); !ok || !got.Planted || !got.Enabled {
		t.Errorf("AWS canary after enable: %+v %v", got, ok)
	}
	// the planted canaries are listed by the API as well
	rec := httptest.NewRecorder()
	s.handleCanaries(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	if !strings.Contains(rec.Body.String(), aws.AccessKeyID) {
		t.Error("API does not list the planted AWS key")
	}

	// a config file that does not parse keeps what is watched
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("honeypots: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !use("203.0.113.11", "aws configure set aws_access_key_id "+aws.AccessKeyID) {
		t.Error("a broken config file dropped the planted canaries")
	}

	// qpot honeypot set cowrie bait=off: no desired artifacts, earlier values
	// remain watched until the operator explicitly disables/deletes the history.
	cli(func(hp *config.HoneypotConfig, _ *config.Config) {
		hp.Enabled = true
		hp.CustomConfig["bait"] = "off"
	})
	if !use("203.0.113.12", "aws configure set aws_secret_access_key "+aws.SecretAccessKey) {
		t.Error("bait off silently dropped a previously planted AWS watch")
	}
	for _, c := range s.canaries.List() {
		if !c.Historical || !c.Planted {
			t.Errorf("bait off: previous watch not marked historical: %+v", c)
		}
	}

	// bait on again with a canary.base_url: the healthcheck's memo follows it
	cli(func(hp *config.HoneypotConfig, cfg *config.Config) {
		hp.Enabled = true
		cfg.Canary.BaseURL = "https://cdn.example.net"
	})
	rec = httptest.NewRecorder()
	s.handleCanaries(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	if !strings.Contains(rec.Body.String(), "https://cdn.example.net/c/") {
		t.Errorf("base_url change not followed: %s", rec.Body.String())
	}
	for _, c := range s.canaries.List() {
		if c.Historical {
			t.Errorf("restored desired bait stayed historical: %+v", c)
		}
	}
}

// TestFollowPlantedLooksAtMostOncePerRecheck: between two looks at the config
// file the server reads nothing (it is not read per event).
func TestFollowPlantedLooksAtMostOncePerRecheck(t *testing.T) {
	old := plantedRecheck
	plantedRecheck = time.Hour
	defer func() { plantedRecheck = old }()
	want, _ := plantedCfg(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := config.Default("plantedonce")
	cfg.QPotID, cfg.DataPath, cfg.ConfigPath = want.QPotID, dir, path
	cfg.Canary.Enabled = true
	off := cfg.Honeypots["cowrie"]
	off.Enabled = false
	cfg.Honeypots["cowrie"] = off
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	cs, err := canary.NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{config: cfg, canaries: cs}
	s.followPlanted() // the first look reads the file
	hp := want.Honeypots["cowrie"]
	cli := config.Default("plantedonce")
	cli.QPotID, cli.DataPath, cli.ConfigPath = want.QPotID, dir, path
	cli.Honeypots["cowrie"] = hp
	if err := config.Save(cli); err != nil {
		t.Fatal(err)
	}
	s.followPlanted()
	if n := len(cs.List()); n != 0 {
		t.Errorf("looked again within the recheck interval: %d canaries", n)
	}
	s.planted.checked = time.Now().Add(-2 * time.Hour)
	s.followPlanted()
	if n := len(cs.List()); n == 0 {
		t.Error("the change was not seen after the recheck interval")
	}
}

// TestFollowPlantedRetriesFailedPersistence checks that a transient store
// failure does not cache the desired config hash and suppress later retries.
func TestFollowPlantedRetriesFailedPersistence(t *testing.T) {
	old := plantedRecheck
	plantedRecheck = 0
	defer func() { plantedRecheck = old }()
	cfg, previous := plantedCfg(t)
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	cs, err := canary.NewStore(cfg.DataPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SyncPlanted(previous); err != nil {
		t.Fatal(err)
	}
	s := &Server{config: cfg, canaries: cs}
	s.followPlanted()
	previousSum := s.planted.sum
	hp, _ := cfg.GetHoneypotConfig("cowrie")
	hp.CustomConfig["bait_profile"] = "industrial"
	cfg.SetHoneypotCustomConfig("cowrie", hp.CustomConfig)
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	desired := instance.PlantedCanaries(cfg)
	storePath := filepath.Join(cfg.DataPath, "canaries.json")
	backupPath := filepath.Join(cfg.DataPath, "prior-canary-store")
	if err := os.Rename(storePath, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(storePath, 0o700); err != nil {
		t.Fatal(err)
	}
	s.followPlanted() // Atomic rename of the store onto a directory must fail.
	if s.planted.sum != previousSum {
		t.Fatal("failed sync cached desired hash and would not retry the same config")
	}
	for _, oldCanary := range previous {
		if c, ok := cs.Get(oldCanary.ID); !ok || c.Historical {
			t.Fatal("failed follower save changed prior active watches")
		}
	}
	for _, newCanary := range desired {
		if _, ok := cs.Get(newCanary.ID); ok {
			t.Fatal("failed follower save partially applied desired watches")
		}
	}
	if err := os.Remove(storePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backupPath, storePath); err != nil {
		t.Fatal(err)
	}
	s.followPlanted() // Identical desired bytes must be retried after recovery.
	for _, newCanary := range desired {
		if c, ok := cs.Get(newCanary.ID); !ok || c.Historical {
			t.Fatal("follower did not recover desired watches after persistence returned")
		}
	}
	for _, oldCanary := range previous {
		if c, ok := cs.Get(oldCanary.ID); !ok || !c.Historical {
			t.Fatal("successful follower retry lost historical watch")
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestMatcherTripsEveryCanaryOfAnEvent: an event that holds several planted
// values gives one canary_trip event for each.
func TestMatcherTripsEveryCanaryOfAnEvent(t *testing.T) {
	cfg, planted := plantedCfg(t)
	cs, err := canary.NewStore(cfg.DataPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SyncPlanted(planted); err != nil {
		t.Fatal(err)
	}
	var cmd []string
	for _, c := range planted {
		switch c.Kind {
		case canary.KindAWS:
			cmd = append(cmd, c.AccessKeyID)
		case canary.KindWeb:
			cmd = append(cmd, c.Token)
		default:
			cmd = append(cmd, c.Values[0])
		}
	}
	db := &fakeDB{}
	m := &canaryMatcher{s: &Server{config: cfg, canaries: cs, database: db}}
	if !m.MatchEvent(context.Background(), &database.Event{Timestamp: time.Now().UTC(), Honeypot: "cowrie",
		SourceIP: "203.0.113.30", EventType: "cowrie.command.input", Command: strings.Join(cmd, " ; ")}) {
		t.Fatal("no trip")
	}
	tripped := map[string]bool{}
	for _, e := range db.insertedEvents() {
		if e.EventType == "canary_trip" {
			tripped[e.Metadata["canary_id"]] = true
		}
	}
	if len(tripped) != len(planted) {
		t.Errorf("%d of %d canaries tripped by one event", len(tripped), len(planted))
	}
}

// First-load failures must be throttled as well as successful reads. Recovery
// retries the same desired YAML after the interval, without caching a failed sum.
func TestFollowPlantedInitialFailuresAreThrottled(t *testing.T) {
	previousInterval := plantedRecheck
	plantedRecheck = time.Hour
	defer func() { plantedRecheck = previousInterval }()
	for _, scenario := range []string{"parse", "persistence"} {
		t.Run(scenario, func(t *testing.T) {
			cfg, desired := plantedCfg(t)
			cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			validConfig, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			store, err := canary.NewStore(cfg.DataPath, 0)
			if err != nil {
				t.Fatal(err)
			}
			storePath := filepath.Join(cfg.DataPath, "canaries.json")
			warning := "canary: config file changed but does not parse"
			if scenario == "parse" {
				if err := os.WriteFile(cfg.ConfigPath, []byte("["), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				// Rename onto a directory fails even when the test process is root.
				if err := os.Mkdir(storePath, 0700); err != nil {
					t.Fatal(err)
				}
				warning = "Canary watches not updated"
			}
			logFile, err := os.CreateTemp(t.TempDir(), "follow-warnings-*.log")
			if err != nil {
				t.Fatal(err)
			}
			previousLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(logFile, nil)))
			defer func() { slog.SetDefault(previousLogger); logFile.Close() }()
			s := &Server{config: cfg, canaries: store}
			for range 3 {
				s.followPlanted()
			}
			attempted := s.planted.checked
			if attempted.IsZero() || s.planted.read {
				t.Fatal("initial failure must record an attempt without a successful config hash")
			}
			logs, err := os.ReadFile(logFile.Name())
			if err != nil {
				t.Fatal(err)
			}
			if count := strings.Count(string(logs), warning); count != 1 {
				t.Fatalf("%s failure attempted/logged %d times inside one recheck interval, want1", scenario, count)
			}
			if scenario == "parse" {
				if err := os.WriteFile(cfg.ConfigPath, validConfig, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(storePath); err != nil {
					t.Fatal(err)
				}
			}
			s.followPlanted()
			if s.planted.read || !s.planted.checked.Equal(attempted) || len(store.List()) != 0 {
				t.Fatal("recovery bypassed the remaining retry interval")
			}
			s.planted.checked = time.Now().Add(-2 * plantedRecheck)
			s.followPlanted()
			if !s.planted.read || s.planted.sum != sha256.Sum256(validConfig) {
				t.Fatal("recovery did not retry and cache the desired config after the interval")
			}
			persisted, err := canary.NewStore(cfg.DataPath, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(store.List()) != len(desired) || len(persisted.List()) != len(desired) {
				t.Fatal("recovered watches were not registered and persisted")
			}
			for _, c := range desired {
				active, ok := persisted.Get(c.ID)
				if !ok || active.Historical || !active.Enabled {
					t.Fatalf("desired watch not active after retry: %s", c.ID)
				}
			}
		})
	}
}
