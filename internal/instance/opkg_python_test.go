package instance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

func TestCowrieOpenWrtPackageTransitions(t *testing.T) {
	cmd := exec.Command(python(t), "-I", filepath.Join("testdata", "cowrie_opkg.py"),
		filepath.Join("honeypotfiles", "cowrie"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenWrt transitions: %v\n%s", err, out)
	}
	var result struct {
		Count  int    `json:"count"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(out, &result); err != nil || result.Result != "PASS" || result.Count == 0 {
		t.Fatalf("OpenWrt transition results: %v %s", err, out)
	}
}

func TestCowriePackageAssetsDeployment(t *testing.T) {
	cfg := config.Default("opkg-assets")
	cfg.DataPath = t.TempDir()
	enableOnly(cfg, "cowrie")
	sandbox, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{config: cfg, sandbox: sandbox}
	if err := manager.generateServiceConfigs(); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		"patch/opkg_assets.zip":        cowrieOpkgAssets,
		"licenses/opkg_sources.tar.xz": cowrieOpkgSources,
		"licenses/opkg-NOTICE.txt":     cowrieOpkgNotice,
	} {
		got, err := os.ReadFile(filepath.Join(cfg.DataPath, "honeypots", "cowrie", path))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("prepared package asset %s: %v", path, err)
		}
	}
	if len(cowrieOpkgAssets) > 2<<20 || len(cowrieOpkgSources) > 32<<20 {
		t.Fatal("finite package assets exceed product bounds")
	}
	for _, asset := range []struct {
		content []byte
		digest  string
	}{
		{cowrieOpkgAssets, "f1965a7fb33198ca08ef2b45e00c11bff336c1a0c0772ecd74e747949ee8fdff"},
		{cowrieOpkgSources, "f2b1a6fb2897f89875b98fb02c7f72df1ea0be7b1a5567f009da5e8c6d6c4498"},
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256(asset.content)); got != asset.digest {
			t.Fatalf("package product artifact digest %s, want %s", got, asset.digest)
		}
	}
	service, _, _ := publishedPorts(t, cfg, "cowrie")
	if !strings.Contains(service, "/patch/opkg_assets.zip:"+cowrieSource+"/commands/opkg_assets.zip:ro\n") {
		t.Fatal("finite runtime package data is not mounted read-only")
	}
	for _, private := range []string{"opkg_sources", "opkg-NOTICE", "/licenses/"} {
		if strings.Contains(service, private) {
			t.Fatalf("operator license asset %q was mounted into guest", private)
		}
	}
}
