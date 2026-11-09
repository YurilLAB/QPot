package cicheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func imageIndexFixture() []byte {
	return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[` +
		`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `","size":480,"platform":{"os":"linux","architecture":"amd64"}},` +
		`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":480,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}}]}`)
}

func TestPublishedImageIndexRejectsMissingOrUnsupportedPlatforms(t *testing.T) {
	good := string(imageIndexFixture())
	for name, data := range map[string]string{
		"empty": "", "not JSON": "no registry index", "null": "null",
		"wrong schema":             strings.Replace(good, `"schemaVersion":2`, `"schemaVersion":1`, 1),
		"single image":             strings.Replace(good, "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json", 1),
		"missing platform":         strings.Replace(good, `"architecture":"arm64"`, `"architecture":""`, 1),
		"duplicate platform":       strings.Replace(good, `"architecture":"arm64","variant":"v8"`, `"architecture":"amd64"`, 1),
		"wrong OS":                 strings.Replace(good, `"os":"linux"`, `"os":"windows"`, 1),
		"unsupported architecture": strings.Replace(good, `"architecture":"arm64"`, `"architecture":"arm"`, 1),
		"newer CPU requirement":    strings.Replace(good, `"variant":"v8"`, `"variant":"v9"`, 1),
		"OS features":              strings.Replace(good, `"architecture":"amd64"`, `"architecture":"amd64","os.features":["required-feature"]`, 1),
		"no manifest size":         strings.Replace(good, `"size":480`, `"size":0`, 1),
		"negative manifest size":   strings.Replace(good, `"size":480`, `"size":-1`, 1),
		"oversized manifest":       strings.Replace(good, `"size":480`, `"size":99999999`, 1),
		"invalid digest":           strings.Replace(good, "sha256:", "sha256:bad", 1),
		"mutable reference":        strings.Replace(good, "sha256:"+strings.Repeat("a", 64), "ghcr.io/example/image:latest", 1),
		"duplicate digest":         strings.Replace(good, strings.Repeat("b", 64), strings.Repeat("a", 64), 1),
		"artifact descriptor":      strings.Replace(good, "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.artifact.manifest.v1+json", 1),
		"duplicate metadata":       strings.Replace(good, `"schemaVersion":2`, `"schemaVersion":1,"schemaVersion":2`, 1),
		"wrong field casing":       strings.Replace(good, `"schemaVersion":2`, `"SCHEMAVERSION":2`, 1),
		"case alias override":      strings.Replace(good, `"schemaVersion":2`, `"schemaVersion":1,"SCHEMAVERSION":2`, 1),
		"platform field casing":    strings.Replace(good, `"os":"linux"`, `"OS":"linux"`, 1),
		"trailing JSON":            good + " {}", "truncated JSON": good[:len(good)-1],
		"too much nesting": strings.Repeat("[", 40) + good + strings.Repeat("]", 40),
		"file size limit":  strings.Repeat(" ", imageIndexLimit) + good,
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkImageIndex([]byte(data)); err == nil {
				t.Fatal("invalid or incomplete published index accepted")
			}
		})
	}
	for name, data := range map[string]string{
		"OCI":         good,
		"Docker":      strings.ReplaceAll(strings.Replace(good, "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", 1), "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"),
		"annotations": strings.Replace(good, `"schemaVersion":2`, `"annotations":{"org.opencontainers.image.title":"QPot"},"schemaVersion":2`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkImageIndex([]byte(data)); err != nil {
				t.Fatalf("supported complete index rejected: %v", err)
			}
		})
	}
}

func TestPublishedImageIndexRequiresRealBoundedOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image-index.json")
	if err := CheckImageIndex(path); err == nil {
		t.Fatal("missing registry output accepted")
	}
	if err := CheckImageIndex(dir); err == nil {
		t.Fatal("directory substituted for registry output")
	}
	if err := os.WriteFile(path, imageIndexFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckImageIndex(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if err := CheckImageIndex(link); err == nil {
			t.Fatal("symlink substituted for actual registry output")
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", imageIndexLimit+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckImageIndex(path); err == nil {
		t.Fatal("oversized registry output accepted")
	}
}

func FuzzPublishedImageIndex(f *testing.F) {
	f.Add(imageIndexFixture())
	f.Add([]byte(`{"schemaVersion":2}`))
	f.Add([]byte(`{"manifests":null,"manifests":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := checkImageIndex(data); err != nil {
			return
		}
		var index publishedImageIndex
		if err := json.Unmarshal(data, &index); err != nil {
			t.Fatal(err)
		}
		canonical, err := json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkImageIndex(canonical); err != nil {
			t.Fatalf("accepted index does not preserve its validated platforms: %v", err)
		}
	})
}
