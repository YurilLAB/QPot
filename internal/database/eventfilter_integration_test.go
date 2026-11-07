package database

import "testing"

// EventFilter.Text and EventTypes against the real backends (each skips
// unless its QPOT_TEST_* switch is set).

func TestClickHouseEventTextAndTypeFilters(t *testing.T) {
	checkEventTextAndTypeFilters(t, connectCH(t), nil, true)
}

func TestPGEventTextAndTypeFilters(t *testing.T) {
	checkEventTextAndTypeFilters(t, connectPG(t), nil, true)
}

func TestESEventTextAndTypeFilters(t *testing.T) {
	es := connectES(t)
	checkEventTextAndTypeFilters(t, es, func() { esRefresh(t, es) }, false)
}

func TestClickHouseCountSlots(t *testing.T) { checkCountSlots(t, connectCH(t), nil) }

func TestPGCountSlots(t *testing.T) { checkCountSlots(t, connectPG(t), nil) }

func TestESCountSlots(t *testing.T) {
	es := connectES(t)
	checkCountSlots(t, es, func() { esRefresh(t, es) })
}
