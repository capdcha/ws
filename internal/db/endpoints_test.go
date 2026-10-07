package db

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/example/warp-server/internal/scanner"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestEndpointLimit(t *testing.T) {
	t.Setenv("MAX_ENDPOINTS", "3")
	d := newTestDB(t)

	if d.maxEndpoints != 3 {
		t.Fatalf("maxEndpoints = %d, want 3", d.maxEndpoints)
	}

	for i := 0; i < 3; i++ {
		ep := &scanner.Endpoint{Host: fmt.Sprintf("10.0.0.%d", i), Port: 500, RTT: 10}
		if err := d.UpsertEndpoint(ep); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	// A brand new endpoint over the limit must be rejected.
	ep := &scanner.Endpoint{Host: "10.0.0.99", Port: 500, RTT: 10}
	if err := d.UpsertEndpoint(ep); err != ErrEndpointLimitReached {
		t.Fatalf("over-limit insert = %v, want ErrEndpointLimitReached", err)
	}

	// Existing rows must keep updating even at the limit.
	update := &scanner.Endpoint{Host: "10.0.0.1", Port: 500, RTT: 42}
	if err := d.UpsertEndpoint(update); err != nil {
		t.Fatalf("update at limit: %v", err)
	}

	all, err := d.GetAllEndpoints()
	if err != nil {
		t.Fatalf("GetAllEndpoints: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("endpoint count = %d, want 3", len(all))
	}
}

func TestEndpointLimitDefault(t *testing.T) {
	t.Setenv("MAX_ENDPOINTS", "")
	if got := maxEndpointsFromEnv(); got != DefaultMaxEndpoints {
		t.Fatalf("maxEndpointsFromEnv() = %d, want %d", got, DefaultMaxEndpoints)
	}
	if DefaultMaxEndpoints != 1000 {
		t.Fatalf("DefaultMaxEndpoints = %d, want 1000", DefaultMaxEndpoints)
	}
}
