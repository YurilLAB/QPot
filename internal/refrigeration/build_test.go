package refrigeration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The minimal context must compile offline by itself, including when emitted
// from an installed QPot without the repository's dependency graph or go.sum.
func TestBundledBuildContextCompilesOffline(t *testing.T) {
	files, err := BuildFiles()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, content := range files {
		if strings.Contains(name, "_test.go") || strings.HasSuffix(name, "/build.go") || name == "go.sum" {
			t.Fatalf("runtime context contains unrelated source: %s", name)
		}
		target := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(root, "refrigeration"), "./cmd/qpot-refrigeration")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("installed context cannot build without module network access: %v\n%s", err, output)
	}
	// Returned bytes are independent; callers cannot change the image identity
	// or source contents the next installation receives.
	files["go.mod"][0] = '!'
	fresh, err := BuildFiles()
	if err != nil || !strings.HasPrefix(string(fresh["go.mod"]), "module ") {
		t.Fatalf("build sources are shared mutable bytes: %v", err)
	}
	image := BuildImage()
	if !strings.HasPrefix(image, "qpot-local/refrigeration:") || len(strings.TrimPrefix(image, "qpot-local/refrigeration:")) != 32 || BuildImage() != image {
		t.Fatalf("invalid or unstable local source image: %s", image)
	}
}
