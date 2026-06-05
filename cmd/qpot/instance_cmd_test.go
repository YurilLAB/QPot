package main

import (
	"io"
	"strings"
	"testing"
)

// runInstance executes `qpot instance <args...>` against a fresh command tree
// and returns any error, with output discarded.
func runInstance(args ...string) error {
	cmd := newInstanceCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

// TestInstanceCreateRefusesClobber guards the data-loss bug where re-running
// `instance create <name>` on an existing instance silently overwrote its config
// and minted a new QPot ID, wiping enabled honeypots and identity. The second
// create must error and leave the first instance untouched.
func TestInstanceCreateRefusesClobber(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := runInstance("create", "p1"); err != nil {
		t.Fatalf("first create should succeed: %v", err)
	}
	err := runInstance("create", "p1")
	if err == nil {
		t.Fatal("re-creating an existing instance must error (would otherwise clobber it)")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should explain the instance exists, got: %v", err)
	}
}

// TestInstanceRemoveNonexistentErrors guards the bug where removing a name that
// does not exist reported success (config.Load auto-creates, so it created then
// deleted an empty instance). It must error instead.
func TestInstanceRemoveNonexistentErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runInstance("remove", "ghost")
	if err == nil {
		t.Fatal("removing a nonexistent instance must error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should say the instance does not exist, got: %v", err)
	}

	// A real instance must still remove cleanly.
	if err := runInstance("create", "real1"); err != nil {
		t.Fatalf("create real1: %v", err)
	}
	if err := runInstance("remove", "real1"); err != nil {
		t.Errorf("removing an existing instance should succeed, got: %v", err)
	}
}
