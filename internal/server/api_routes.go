package server

// setupAPIRoutes registers the web UI's endpoints for QPot's features beyond
// the original dashboard API (doc/api.md). Every one requires the QPot ID;
// the server's middleware also requires a JSON body type on writes.
func (s *Server) setupAPIRoutes() {
	s.mux.HandleFunc("/api/honeypots/settings", s.withQPotAuth(s.handleHoneypotSettings))
	s.mux.HandleFunc("/api/honeypots/restart", s.withQPotAuth(s.handleHoneypotRestart))
	s.mux.HandleFunc("/api/instance", s.withQPotAuth(s.handleInstance))
	s.mux.HandleFunc("/api/doctor", s.withQPotAuth(s.handleDoctor))
	s.mux.HandleFunc("/api/doctor/explain", s.withQPotAuth(s.handleDoctorExplain))
	s.mux.HandleFunc("/api/doctor/codes", s.withQPotAuth(s.handleDoctorCodes))
	s.mux.HandleFunc("/api/cluster/requests", s.withQPotAuth(s.handleClusterRequests))
	s.mux.HandleFunc("/api/pulse", s.withQPotAuth(s.handlePulse))
}
