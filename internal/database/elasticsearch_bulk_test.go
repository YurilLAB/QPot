package database

import (
	"strings"
	"testing"
)

// TestCheckBulkErrors guards the fix for the silent-data-loss bug: the ES _bulk
// API returns HTTP 200 even when individual items fail, so checking the status
// code alone treated partial failures as success. checkBulkErrors must surface a
// failure when the response's "errors" flag is set and items carry errors.
func TestCheckBulkErrors(t *testing.T) {
	t.Run("all succeeded", func(t *testing.T) {
		body := []byte(`{"errors":false,"items":[{"index":{"status":201}},{"index":{"status":201}}]}`)
		if err := checkBulkErrors(body, 2); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
	t.Run("partial failure is surfaced", func(t *testing.T) {
		body := []byte(`{"errors":true,"items":[
			{"index":{"status":201}},
			{"index":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"failed to parse field x"}}}
		]}`)
		err := checkBulkErrors(body, 2)
		if err == nil {
			t.Fatal("expected an error for a partial bulk failure, got nil")
		}
		if !strings.Contains(err.Error(), "1/2") || !strings.Contains(err.Error(), "failed to parse field x") {
			t.Errorf("error should report the count and reason, got: %v", err)
		}
	})
	t.Run("errors flag but no item errors", func(t *testing.T) {
		// Defensive: errors=true with no per-item error objects -> treat as ok.
		body := []byte(`{"errors":true,"items":[{"index":{"status":201}}]}`)
		if err := checkBulkErrors(body, 1); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
	t.Run("unparseable body does not mask 2xx", func(t *testing.T) {
		if err := checkBulkErrors([]byte("not json"), 1); err != nil {
			t.Errorf("expected nil for unparseable body, got %v", err)
		}
	})
}
