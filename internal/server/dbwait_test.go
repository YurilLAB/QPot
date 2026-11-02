package server

import (
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// Unit tests point New at an unreachable database on purpose; they must not
// sit through the production startup wait.
func init() { dbStartupWait = 0 }

// New must keep retrying an unreachable database until dbStartupWait elapses
// (the database container is usually still starting), then come up DB-less.
func TestConnectDatabaseWaitsThenGivesUp(t *testing.T) {
	old := dbStartupWait
	dbStartupWait = 3 * time.Second
	defer func() { dbStartupWait = old }()
	cfg := config.Default("db-wait-test")
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = 1 // nothing listens here
	start := time.Now()
	if db := connectDatabase(cfg); db != nil {
		t.Fatal("connectDatabase returned a database for an unreachable server")
	}
	if waited := time.Since(start); waited < 3*time.Second {
		t.Fatalf("gave up after %v, want to keep retrying for the startup wait", waited)
	}
}
