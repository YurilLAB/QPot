package refrigeration

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"sync"
)

// buildSource contains the same emulator sources and assets compiled into QPot.
// The build helper and tests are deliberately absent from the runtime context.
//
//go:embed server.go model.go xml.go events.go persistence.go assets Dockerfile
var buildSource embed.FS

const buildModule = "module github.com/qpot/qpot\n\ngo 1.26.0\n"

// buildMain is only process wiring. All protocol, state and UI behavior comes
// from the exact embedded implementation above, not a second emulator.
const buildMain = `package main
import (
 "context"
 "fmt"
 "os"
 "os/signal"
 "syscall"
 "github.com/qpot/qpot/internal/refrigeration"
)
func main() {
 ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
 defer stop()
 if err := refrigeration.Command(ctx, os.Args[1:]); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
`

// BuildFiles returns an independent, complete Docker build context. It lets an
// installed QPot binary build this native honeypot with Docker alone: no host
// compiler, source checkout or unpublished registry image is required.
func BuildFiles() (map[string][]byte, error) {
	files := map[string][]byte{
		"go.mod":                         []byte(buildModule),
		"cmd/qpot-refrigeration/main.go": []byte(buildMain),
	}
	err := fs.WalkDir(buildSource, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := buildSource.ReadFile(path)
		if err != nil {
			return err
		}
		target := "internal/refrigeration/" + path
		if path == "Dockerfile" {
			target = "Dockerfile"
		}
		files[target] = data
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read embedded refrigeration sources: %w", err)
	}
	return files, nil
}

// BuildImage returns a local image name tied to all bundled source contents.
// A source change therefore cannot accidentally reuse an older running image.
func BuildImage() string {
	return localBuildImage()
}

var localBuildImage = sync.OnceValue(func() string {
	files, err := BuildFiles()
	if err != nil {
		// embed.FS is immutable and WalkDir supplies only existing paths. This
		// indicates a broken binary, not a request or environmental failure.
		panic(err)
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		_, _ = fmt.Fprintf(h, "%d:%s:%d:", len(path), path, len(files[path]))
		_, _ = h.Write(files[path])
	}
	return "qpot-local/refrigeration:" + hex.EncodeToString(h.Sum(nil)[:16])
})
