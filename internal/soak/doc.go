// Package soak is QPot's long-duration failure test. It has no production
// code: its test drives a real instance on real Docker with steady attack
// traffic, breaks one part at a time on a schedule, and measures what an
// operator would ask afterwards:
//
//   - how many events the honeypot accepted and the database never got (lost);
//   - how many it got twice (duplicated), in events and in intelligence;
//   - how long each fault delayed delivery, and how long recovery took.
//
// It runs only when asked, against an instance it creates and removes:
//
//	QPOT_SOAK=1 QPOT_SOAK_BIN=/path/to/qpot QPOT_SOAK_DURATION=4h \
//	    go test ./internal/soak -run TestSoak -timeout 0 -v
//
// See doc/reliability.md for every setting, the faults, how each number is
// measured and the results of the last recorded run.
package soak
