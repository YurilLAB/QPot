package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/intelligence"
)

// newOutboxTestServer builds a server with the canary subsystem, its outbox
// and store under dir (the instance data directory), and db when not nil -
// what server.New sets up.
func newOutboxTestServer(t *testing.T, db *flakyDB, dir string) *Server {
	t.Helper()
	cs, err := canary.NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		config: &config.Config{QPotID: validTestID, DataPath: dir,
			Canary: config.CanaryConfig{Enabled: true, BaseURL: "https://assets.example.com", Decoy: "notfound"}},
		mux:        http.NewServeMux(),
		canaries:   cs,
		classifier: intelligence.NewClassifier(intelligence.NewATTCKLoader(t.TempDir()), nil),
	}
	if s.canaryOutbox, err = newCanaryOutbox(dir); err != nil {
		t.Fatal(err)
	}
	if db != nil {
		s.database = db
	}
	s.setupRoutes()
	return s
}

// replayPending runs one pass of the outbox loop.
func replayPending(t *testing.T, s *Server) {
	t.Helper()
	s.replayCanaryOutbox(context.Background())
}
