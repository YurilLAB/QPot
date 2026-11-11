package diskguard

import (
	"testing"
	"time"
)

const mb = int64(1) << 20

// def are the default marks: stop below 512 MB, resume at 1024 MB.
var def = FromMB(512, 1024)

func known(freeMB int64) Reading { return Reading{Free: freeMB * mb, Known: true} }

func TestFromMB(t *testing.T) {
	cases := []struct {
		min, resume  int64
		wantMin, res int64
		on           bool
	}{
		{512, 1024, 512 * mb, 1024 * mb, true},
		{0, 1024, 0, 1024 * mb, false},
		{-5, -5, 0, 0, false},
		{1, 2, mb, 2 * mb, true},
		// Far too large: capped, never negative.
		{1 << 60, 1 << 62, (1 << 42) * mb, (1 << 42) * mb, true},
	}
	for _, c := range cases {
		got := FromMB(c.min, c.resume)
		if got.MinFree != c.wantMin || got.ResumeFree != c.res || got.On() != c.on {
			t.Errorf("FromMB(%d, %d) = %+v on=%v, want {%d %d} on=%v", c.min, c.resume, got, got.On(), c.wantMin, c.res, c.on)
		}
		if got.MinFree < 0 || got.ResumeFree < 0 {
			t.Errorf("FromMB(%d, %d) overflowed: %+v", c.min, c.resume, got)
		}
	}
}

// TestNextSingleReadings: one reading on a fresh machine.
func TestNextSingleReadings(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		t    Thresholds
		r    Reading
		held bool
		want Action
	}{
		{"plenty of room", def, known(5000), false, None},
		{"plenty of room, honeypots held", def, known(5000), true, Resume},
		{"exactly the resume mark, held", def, known(1024), true, Resume},
		{"one byte below the resume mark, held", def, Reading{Free: 1024*mb - 1, Known: true}, true, None},
		{"between the marks", def, known(700), false, None},
		{"between the marks, held", def, known(700), true, None},
		{"exactly the floor", def, known(512), false, None},
		{"one byte below the floor: cleanup first", def, Reading{Free: 512*mb - 1, Known: true}, false, Cleanup},
		{"full disk is known, not unknown", def, Reading{Free: 0, Known: true}, false, Cleanup},
		{"unknown free space", def, Reading{}, false, None},
		{"unknown free space, held", def, Reading{}, true, None},
		{"unknown free space with a number", def, Reading{Free: 5, Known: false}, true, None},
		{"guard off, full disk", FromMB(0, 1024), known(0), false, None},
		{"guard off, unknown", FromMB(0, 0), Reading{}, false, None},
		{"guard off gives back what it holds", FromMB(0, 1024), known(0), true, Resume},
		{"guard off gives back even when the disk is unknown", FromMB(0, 0), Reading{}, true, Resume},
		{"resume mark below the floor counts as the floor", Thresholds{MinFree: 512 * mb, ResumeFree: 10 * mb}, known(512), true, Resume},
		{"resume mark below the floor, below the floor", Thresholds{MinFree: 512 * mb, ResumeFree: 10 * mb}, known(511), true, Cleanup},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var m Machine
			if got := m.Next(now, c.t, c.r, c.held); got != c.want {
				t.Errorf("Next = %v, want %v", got, c.want)
			}
		})
	}
}

// step is one reading in a run and what the machine must answer. A Cleanup
// answer is followed, as the caller does, by a second Next with the reading
// after the cleanup (after) at the same moment.
type step struct {
	at    time.Duration
	free  Reading
	held  bool
	want  Action
	after *Reading // the reading after a cleanup
	then  Action   // the answer to it
}

func runSteps(t *testing.T, th Thresholds, steps []step) {
	t.Helper()
	start := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var m Machine
	for i, s := range steps {
		now := start.Add(s.at)
		got := m.Next(now, th, s.free, s.held)
		if got != s.want {
			t.Fatalf("step %d (free %d MB known=%v held=%v): %v, want %v", i, s.free.Free/mb, s.free.Known, s.held, got, s.want)
		}
		if got != Cleanup {
			continue
		}
		if s.after == nil {
			t.Fatalf("step %d answered cleanup, and the test gives no reading after it", i)
		}
		if again := m.Next(now, th, *s.after, s.held); again != s.then {
			t.Fatalf("step %d after the cleanup (free %d MB): %v, want %v", i, s.after.Free/mb, again, s.then)
		}
	}
}

func after(freeMB int64) *Reading { r := known(freeMB); return &r }

// TestHysteresis: stopped below the floor, the honeypots stay stopped all
// the way up to the resume mark, and a disk that swings between the two
// marks neither stops nor starts anything.
func TestHysteresis(t *testing.T) {
	s := 5 * time.Second
	runSteps(t, def, []step{
		{at: 0, free: known(2000), want: None},
		{at: 1 * s, free: known(400), want: Cleanup, after: after(400), then: Stop},
		{at: 2 * s, free: known(400), held: true, want: Stop},
		// Stopping freed nothing much; the disk creeps up between the marks.
		{at: 3 * s, free: known(512), held: true, want: None},
		{at: 4 * s, free: known(600), held: true, want: None},
		{at: 5 * s, free: known(1023), held: true, want: None},
		{at: 6 * s, free: known(513), held: true, want: None},
		{at: 7 * s, free: known(1023), held: true, want: None},
		// Dips below the floor again: stop again, no second cleanup so soon.
		{at: 8 * s, free: known(500), held: true, want: Stop},
		{at: 9 * s, free: known(900), held: true, want: None},
		// Only the resume mark starts them.
		{at: 10 * s, free: known(1024), held: true, want: Resume},
		{at: 11 * s, free: known(1024), held: false, want: None},
		// Back between the marks with nothing held: nothing happens, in
		// either direction.
		{at: 12 * s, free: known(600), want: None},
		{at: 13 * s, free: known(1023), want: None},
		{at: 14 * s, free: known(512), want: None},
		// A new low spell starts with a cleanup again.
		{at: 15 * s, free: known(511), want: Cleanup, after: after(100), then: Stop},
		{at: 16 * s, free: known(100), held: true, want: Stop},
	})
}

// TestCleanupRecovers: when the cleanup frees enough, nothing is stopped.
func TestCleanupRecovers(t *testing.T) {
	s := 5 * time.Second
	t.Run("to above the resume mark", func(t *testing.T) {
		runSteps(t, def, []step{
			{at: 0, free: known(300), want: Cleanup, after: after(3000), then: None},
			{at: 1 * s, free: known(3000), want: None},
			// That spell is over: the next one gets its own cleanup.
			{at: 2 * s, free: known(300), want: Cleanup, after: after(300), then: Stop},
		})
	})
	t.Run("to between the marks", func(t *testing.T) {
		runSteps(t, def, []step{
			{at: 0, free: known(300), want: Cleanup, after: after(700), then: None},
			{at: 1 * s, free: known(700), want: None},
			// Still the same spell: below the floor again stops at once.
			{at: 2 * s, free: known(300), want: Stop},
			{at: 3 * s, free: known(300), held: true, want: Stop},
		})
	})
	t.Run("to above the resume mark with honeypots held from before", func(t *testing.T) {
		runSteps(t, def, []step{
			{at: 0, free: known(300), held: true, want: Cleanup, after: after(3000), then: Resume},
		})
	})
}

// TestCleanupIsRetried: while the disk stays below the floor, cleanup is
// asked for again every CleanupRetry, not on every reading.
func TestCleanupIsRetried(t *testing.T) {
	runSteps(t, def, []step{
		{at: 0, free: known(100), want: Cleanup, after: after(100), then: Stop},
		{at: 5 * time.Second, free: known(100), held: true, want: Stop},
		{at: CleanupRetry - time.Second, free: known(100), held: true, want: Stop},
		{at: CleanupRetry, free: known(100), held: true, want: Cleanup, after: after(100), then: Stop},
		{at: CleanupRetry + 5*time.Second, free: known(100), held: true, want: Stop},
		{at: 2*CleanupRetry - time.Second, free: known(100), held: true, want: Stop},
		{at: 2 * CleanupRetry, free: known(100), held: true, want: Cleanup, after: after(2000), then: Resume},
	})
}

// TestUnknownChangesNothing: readings that fail neither stop nor start
// anything, and do not end a low spell.
func TestUnknownChangesNothing(t *testing.T) {
	s := 5 * time.Second
	runSteps(t, def, []step{
		{at: 0, free: Reading{}, want: None},
		{at: 1 * s, free: known(100), want: Cleanup, after: &Reading{}, then: None},
		{at: 2 * s, free: Reading{}, held: false, want: None},
		{at: 3 * s, free: known(100), want: Stop},
		{at: 4 * s, free: Reading{}, held: true, want: None},
		{at: 5 * s, free: known(100), held: true, want: Stop},
	})
}

// TestGuardTurnedOffWhileHolding: turning the guard off starts what it
// holds, and turning it on again starts a new spell.
func TestGuardTurnedOffWhileHolding(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var m Machine
	if got := m.Next(now, def, known(100), false); got != Cleanup {
		t.Fatalf("first: %v", got)
	}
	if got := m.Next(now, def, known(100), false); got != Stop {
		t.Fatalf("after cleanup: %v", got)
	}
	off := FromMB(0, 0)
	if got := m.Next(now.Add(5*time.Second), off, known(100), true); got != Resume {
		t.Fatalf("turned off while holding: %v, want resume", got)
	}
	if got := m.Next(now.Add(10*time.Second), off, known(100), false); got != None {
		t.Fatalf("off, nothing held: %v", got)
	}
	if got := m.Next(now.Add(15*time.Second), def, known(100), false); got != Cleanup {
		t.Fatalf("turned on again below the floor: %v, want cleanup", got)
	}
}

// TestClockSetBack: a clock that jumps back does not hold cleanup off for
// longer than CleanupRetry.
func TestClockSetBack(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var m Machine
	if got := m.Next(now, def, known(100), false); got != Cleanup {
		t.Fatalf("first: %v", got)
	}
	if got := m.Next(now.Add(-24*time.Hour), def, known(100), true); got != Cleanup {
		t.Fatalf("after the clock went back a day: %v, want cleanup", got)
	}
	if got := m.Next(now.Add(-24*time.Hour+time.Second), def, known(100), true); got != Stop {
		t.Fatalf("a second later: %v, want stop", got)
	}
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		t    Thresholds
		r    Reading
		held bool
		want Condition
	}{
		{FromMB(0, 0), known(0), false, Off},
		{FromMB(0, 0), known(0), true, Off},
		{def, Reading{}, false, Unknown},
		{def, Reading{}, true, Unknown},
		{def, known(0), false, Low},
		{def, known(511), true, Low},
		{def, known(512), true, Waiting},
		{def, known(5000), true, Waiting},
		{def, known(512), false, OK},
		{def, known(5000), false, OK},
	}
	for _, c := range cases {
		if got := Describe(c.t, c.r, c.held); got != c.want {
			t.Errorf("Describe(%+v, %+v, %v) = %q, want %q", c.t, c.r, c.held, got, c.want)
		}
	}
}

func TestActionString(t *testing.T) {
	for a, want := range map[Action]string{None: "none", Cleanup: "cleanup", Stop: "stop", Resume: "resume", Action(99): "unknown"} {
		if got := a.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", int(a), got, want)
		}
	}
}
