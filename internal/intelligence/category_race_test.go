//go:build race

package intelligence

// catRaceEnabled reports a build with the race detector, which slows code
// several times over (see TestCategorizeHostileInputIsFast).
const catRaceEnabled = true
