package proxy

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CaptureHeartbeat is the file in the generations folder that the host's
// capture converter rewrites while it runs. Backends record their sessions
// in their container logs, which hold only so much: the broker admits a new
// connection only while the converter is turning those logs into evidence,
// so nothing piles up unconverted while the control plane is down.
const CaptureHeartbeat = ".capture"

// CaptureStale is how long after the heartbeat last changed the broker still
// trusts the converter.
const CaptureStale = 30 * time.Second

// WatchCapture samples the converter's heartbeat until ctx ends.
func (g *GenerationGate) WatchCapture(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		g.sampleCapture()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sampleCapture notes when the heartbeat last changed, by the broker's own
// clock: the host's clock (a Docker Desktop VM's, say) may differ.
func (g *GenerationGate) sampleCapture() {
	value := ""
	if f, err := os.Open(filepath.Join(g.dir, CaptureHeartbeat)); err == nil {
		data, _ := io.ReadAll(io.LimitReader(f, 64))
		_ = f.Close()
		value = strings.TrimSpace(string(data))
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if value == "" {
		return
	}
	if g.captureSeen && value != g.captureValue {
		g.captureChanged = g.now()
	}
	g.captureSeen, g.captureValue = true, value
}

// CaptureLive reports whether the converter's heartbeat changed within
// CaptureStale. A broker that has not yet seen it change is not live.
func (g *GenerationGate) CaptureLive() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.captureChanged.IsZero() && g.now().Sub(g.captureChanged) < CaptureStale
}
