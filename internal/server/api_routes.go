package server

// setupAPIRoutes registers the web UI's endpoints for QPot's features beyond
// the original dashboard API (doc/api.md). Every one requires the QPot ID;
// the server's middleware also requires a JSON body type on writes.
func (s *Server) setupAPIRoutes() {
	s.mux.HandleFunc("/api/honeypots/settings", s.withQPotAuth(s.handleHoneypotSettings))
}
