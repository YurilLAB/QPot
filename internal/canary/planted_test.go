package canary

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// planted builds planted canaries of every watched kind from one seed.
func planted(seed string) []*Canary {
	d := NewDeriver(seed)
	id, secret := d.AWSKeyPair("aws")
	return []*Canary{
		{ID: d.ID("aws"), Kind: KindAWS, Name: "aws", AccessKeyID: id, SecretAccessKey: secret, Planted: true},
		{ID: d.ID("db"), Kind: KindCredential, Name: "db", Values: []string{d.Secret("db", 18)}, Planted: true},
		{ID: d.ID("key"), Kind: KindSSHKey, Name: "key", Values: []string{d.Secret("blob", 51), "aa:bb:cc:dd:ee:ff:00:11"}, Planted: true},
		{ID: d.ID("ping"), Kind: KindWeb, Name: "ping", Token: d.BeaconToken("ping"), Planted: true},
	}
}

// TestSyncPlanted: planted canaries are added and watched, keep their state
// across syncs, follow changed values, remain historical when no longer planned,
// and never alter an operator's canaries.
func TestSyncPlanted(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	own, err := s.Create(KindAWS, "operator", "jenkins")
	if err != nil {
		t.Fatal(err)
	}
	p := planted("one")
	if err := s.SyncPlanted(p); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 5 {
		t.Fatalf("%d canaries after sync, want 5", len(s.List()))
	}
	// every kind trips on its value in a honeypot session
	for i, text := range []string{"export AWS_SECRET_ACCESS_KEY=" + p[0].SecretAccessKey,
		"mysql -p'" + p[1].Values[0] + "'", "key " + p[2].Values[1], "curl http://10.0.0.5:8000/ping/" + p[3].Token} {
		tr, ok, err := s.Match(text, "198.51.100."+string(rune('1'+i)), "cowrie")
		if err != nil || !ok || tr.CanaryID != p[i].ID {
			t.Fatalf("%s did not trip on %q (ok=%v err=%v)", p[i].Kind, text, ok, err)
		}
	}
	// a disabled planted canary stays disabled and keeps its trips through a sync
	if ok, err := s.SetEnabled(p[1].ID, false); !ok || err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(filepath.Join(dir, "canaries.json"))
	time.Sleep(20 * time.Millisecond)
	if err := s.SyncPlanted(planted("one")); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.Stat(filepath.Join(dir, "canaries.json")); !again.ModTime().Equal(stat.ModTime()) {
		t.Error("an unchanged sync rewrote the store")
	}
	db, _ := s.Get(p[1].ID)
	if db.Enabled || db.Trips != 1 || !db.Planted {
		t.Fatalf("sync lost the state of a planted canary: %+v", db)
	}
	// reloaded from disk, the planted canaries are still watched
	re, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := re.Match("AKIA? "+p[0].AccessKeyID, "203.0.113.9", "cowrie"); !ok {
		t.Fatal("planted canary not watched after a reload")
	}
	// new values replace the old ones in the watch list
	changed := planted("one")
	old := changed[1].Values[0]
	changed[1].Values = []string{strings.Repeat("N", 20)}
	if err := s.SyncPlanted(changed); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Get(p[1].ID); c.Enabled || c.Trips != 1 {
		t.Fatalf("a planted canary with new values lost its state: %+v", c)
	}
	if ok, _ := s.SetEnabled(p[1].ID, true); !ok {
		t.Fatal("planted canary gone")
	}
	if _, ok, _ := s.Match("-p"+old, "203.0.113.10", "cowrie"); ok {
		t.Fatal("an old planted value still trips")
	}
	if _, ok, _ := s.Match("-p"+strings.Repeat("N", 20), "203.0.113.11", "cowrie"); !ok {
		t.Fatal("the new planted value does not trip")
	}
	// No longer planned: retain watches as historical, including copied values
	// or an old process after a failed recreation. The operator's canary stays.
	before := len(s.Trips(0))
	if err := s.SyncPlanted(nil); err != nil {
		t.Fatal(err)
	}
	if got := s.List(); len(got) != 5 {
		t.Fatalf("after an empty sync: %d canaries", len(got))
	}
	if manual, ok := s.Get(own.ID); !ok || manual.Planted || manual.Historical {
		t.Fatal("history reconciliation changed the operator's canary")
	}
	for _, pc := range p {
		if historical, ok := s.Get(pc.ID); !ok || !historical.Planted || !historical.Historical {
			t.Fatalf("previously planted canary not retained: %+v", historical)
		}
	}
	if len(s.Trips(0)) != before {
		t.Fatal("retiring planted canaries dropped their trips")
	}
	if _, ok, _ := s.Match(p[0].AccessKeyID, "203.0.113.12", "cowrie"); !ok {
		t.Fatal("a historical planted canary is no longer watched")
	}
}

func TestHistoricalPlantedStatePersistsAndReactivates(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := planted("historical")
	if err := s.SyncPlanted(p); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetEnabled(p[1].ID, false); !ok || err != nil {
		t.Fatal(err)
	}
	if err := s.SyncPlanted(nil); err != nil {
		t.Fatal(err)
	}
	// A fixed old mtime proves an already historical sync does no write, without
	// depending on wall-clock sleep or filesystem timestamp granularity.
	path := filepath.Join(dir, "canaries.json")
	at := time.Unix(1600000000, 0)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncPlanted(nil); err != nil {
		t.Fatal(err)
	}
	if stat, err := os.Stat(path); err != nil || !stat.ModTime().Equal(at) {
		t.Fatalf("unchanged historical sync rewrote store: %v", err)
	}
	re, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range p {
		c, ok := re.Get(pc.ID)
		if !ok || !c.Planted || !c.Historical || c.Enabled != (pc.ID != p[1].ID) {
			t.Fatalf("historical watch state lost after reload: %+v", c)
		}
	}
	if _, hit, err := re.Match(p[1].Values[0], "203.0.113.30", "cowrie"); hit || err != nil {
		t.Fatalf("disabled historical credential tripped: %v %v", hit, err)
	}
	if _, hit, err := re.Match(p[0].AccessKeyID, "203.0.113.31", "cowrie"); !hit || err != nil {
		t.Fatalf("enabled historical credential did not trip: %v %v", hit, err)
	}
	if err := re.SyncPlanted(p); err != nil {
		t.Fatal(err)
	}
	for _, pc := range p {
		c, _ := re.Get(pc.ID)
		if c.Historical || c.Enabled != (pc.ID != p[1].ID) {
			t.Fatalf("reactivating overwrote enabled state: %+v", c)
		}
	}
	if err := re.SyncPlanted(nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := re.Delete(p[0].ID); !ok || err != nil {
		t.Fatalf("cannot delete a historical watch: %v %v", ok, err)
	}
	if err := re.SyncPlanted(nil); err != nil {
		t.Fatal(err)
	}
	if _, exists := re.Get(p[0].ID); exists {
		t.Fatal("deleted historical watch returned despite being absent from plan")
	}
	if _, hit, err := re.Match(p[0].AccessKeyID, "203.0.113.32", "cowrie"); hit || err != nil {
		t.Fatalf("deleted history remains indexed: %v %v", hit, err)
	}
}

func TestSyncPlantedSaveFailureRestoresRegistryAndIndexes(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	previous, desired := planted("previous-plan"), planted("desired-plan")
	revised := *previous[2]
	revised.Values = []string{strings.Repeat("r", 32)}
	desired = append(desired, &revised) // Exercise replacement/deindex rollback too.
	if err := s.SyncPlanted(previous); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(KindWeb, "operator", "manual must survive"); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(s.canaries)
	oldTokens, oldValues := maps.Clone(s.byToken), maps.Clone(s.byValue)
	oldPath := s.path
	diskBefore, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	// Rename of a regular temp file onto a directory reliably fails, including
	// privileged test runners where chmod-based permission tests would not.
	s.path = filepath.Join(t.TempDir(), "blocked-target")
	if err := os.Mkdir(s.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncPlanted(desired); err == nil {
		t.Fatal("sync unexpectedly persisted onto a directory")
	}
	after, _ := json.Marshal(s.canaries)
	if !bytes.Equal(before, after) || !reflect.DeepEqual(oldTokens, s.byToken) || !reflect.DeepEqual(oldValues, s.byValue) {
		t.Fatal("failed sync changed registry, historical flags or lookup indexes")
	}
	diskAfter, err := os.ReadFile(oldPath)
	if err != nil || !bytes.Equal(diskBefore, diskAfter) {
		t.Fatalf("failed sync changed previously persisted state: %v", err)
	}
	s.path = oldPath
	if _, hit, err := s.Match(previous[1].Values[0], "203.0.113.41", "old process"); !hit || err != nil {
		t.Fatalf("old active credential was lost after failed sync: %v %v", hit, err)
	}
	if _, hit, err := s.Match(desired[1].Values[0], "203.0.113.42", "not applied"); hit || err != nil {
		t.Fatalf("unpersisted desired credential became watched: %v %v", hit, err)
	}
	if _, hit, err := s.TripByToken(previous[3].Token, "203.0.113.43", "test", "GET", Origin{}); !hit || err != nil {
		t.Fatalf("old token index lost after failed sync: %v %v", hit, err)
	}
	if err := s.SyncPlanted(desired); err != nil {
		t.Fatalf("retry did not recover: %v", err)
	}
	if c, ok := s.Get(previous[1].ID); !ok || !c.Historical || c.Trips != 1 {
		t.Fatalf("successful retry lost previous watch/trips: %+v", c)
	}
}

// TestSyncPlantedRefusesOthers: only planted canaries with an ID are synced.
func TestSyncPlantedRefusesOthers(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 0)
	for _, bad := range [][]*Canary{
		{{ID: "cnry_1", Kind: KindCredential}},           // not planted
		{{ID: "x", Kind: KindCredential, Planted: true}}, // no canary ID
		{{ID: "cnry_2", Kind: "bogus", Planted: true}},   // unknown kind
		{nil}, // nothing
		{{ID: "cnry_3", Kind: KindWeb, Planted: true}, {ID: "cnry_3", Kind: KindWeb, Planted: true}}, // twice
	} {
		if err := s.SyncPlanted(bad); err == nil {
			t.Errorf("synced %+v", bad)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("a refused sync left canaries")
	}
}

// TestPlantedNotDeletable: QPot plants them again on the next start, so the
// store refuses to delete one; disabling works.
func TestPlantedNotDeletable(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 0)
	p := planted("del")
	if err := s.SyncPlanted(p); err != nil {
		t.Fatal(err)
	}
	ok, err := s.Delete(p[0].ID)
	if ok || !errors.Is(err, ErrPlanted) {
		t.Fatalf("Delete of a planted canary: ok=%v err=%v", ok, err)
	}
	if _, found := s.Get(p[0].ID); !found {
		t.Fatal("planted canary deleted")
	}
	if ok, err := s.SetEnabled(p[0].ID, false); !ok || err != nil {
		t.Fatal("cannot disable a planted canary")
	}
	if _, tripped, _ := s.Match(p[0].AccessKeyID, "203.0.113.5", "cowrie"); tripped {
		t.Fatal("disabled planted canary tripped")
	}
}

// TestShortValuesNotWatched: a value shorter than MinWatchLen could turn up in
// a session by chance and is never watched.
func TestShortValuesNotWatched(t *testing.T) {
	c := &Canary{Kind: KindCredential, Values: []string{"root", "123456", strings.Repeat("v", MinWatchLen-1),
		strings.Repeat("w", MinWatchLen)}}
	if got := c.watchValues(); len(got) != 1 || got[0] != strings.Repeat("w", MinWatchLen) {
		t.Fatalf("watched %q", got)
	}
}

// TestKindsCreatableAndTechniques: the API mints only web, file and aws
// canaries; the planted kinds map to Unsecured Credentials.
func TestKindsCreatableAndTechniques(t *testing.T) {
	for _, k := range []Kind{KindWeb, KindFile, KindAWS} {
		if !k.Creatable() || !k.Valid() {
			t.Errorf("%s not creatable", k)
		}
	}
	for _, k := range []Kind{KindCredential, KindSSHKey} {
		if k.Creatable() || !k.Valid() {
			t.Errorf("%s: creatable=%v valid=%v", k, k.Creatable(), k.Valid())
		}
	}
	for k, want := range map[Kind]string{KindCredential: "T1552.001", KindSSHKey: "T1552.004"} {
		ev := (&Trip{Kind: k, Channel: "honeypot", Name: "n"}).ToEvent()
		if ev.TechniqueID != want || ev.TacticID != "TA0006" || ev.Protocol != "credential" {
			t.Errorf("%s: %s %s %s", k, ev.TechniqueID, ev.TacticID, ev.Protocol)
		}
	}
}

// TestMatchAllTripsEveryCanaryOfAnEvent: one captured command that uses
// several stolen values (the backup script pasted back, a key and a password
// on one line) trips each of their canaries, once; a canary that tripped a
// moment ago from the same source is folded into that trip and does not hide
// the others.
func TestMatchAllTripsEveryCanaryOfAnEvent(t *testing.T) {
	s, err := NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	p := planted("all")
	if err := s.SyncPlanted(p); err != nil {
		t.Fatal(err)
	}
	// the database password trips first, alone
	if tr, ok, _ := s.Match("mysql -p'"+p[1].Values[0]+"'", "203.0.113.20", "cowrie"); !ok || tr.CanaryID != p[1].ID {
		t.Fatalf("db password: %+v %v", tr, ok)
	}
	// then a line with the password again, the AWS key (both halves) and the URL
	line := "DB_PASS='" + p[1].Values[0] + "' AWS_ACCESS_KEY_ID=" + p[0].AccessKeyID + " AWS_SECRET_ACCESS_KEY=" +
		p[0].SecretAccessKey + " curl http://10.0.0.5:8000/ping/" + p[3].Token
	for round := 0; round < 3; round++ {
		trips, err := s.MatchAll(line, "203.0.113.20", "cowrie")
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, tr := range trips {
			got = append(got, tr.CanaryID)
		}
		want := []string{p[0].ID, p[3].ID}
		if p[3].ID < p[0].ID {
			want = []string{p[3].ID, p[0].ID}
		}
		if round > 0 {
			want = nil // all of them repeats now
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("round %d: tripped %v, want %v", round, got, want)
		}
	}
	// a disabled canary in the same line stays silent, the others trip
	if ok, err := s.SetEnabled(p[2].ID, false); !ok || err != nil {
		t.Fatal(err)
	}
	trips, _ := s.MatchAll("key "+p[2].Values[1]+" and "+p[0].AccessKeyID, "203.0.113.21", "cowrie")
	if len(trips) != 1 || trips[0].CanaryID != p[0].ID {
		t.Errorf("disabled key in the line: %+v", trips)
	}
	if c, _ := s.Get(p[1].ID); c.Trips != 4 {
		t.Errorf("db password counted %d hits, want 4", c.Trips)
	}
}
