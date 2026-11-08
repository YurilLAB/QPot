package instance

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"gopkg.in/yaml.v3"
)

// tpotPathExceptions are T-Pot reference-compose mounts QPot leaves out on
// purpose, with the reason.
var tpotPathExceptions = map[string]map[string]string{
	// ddospot v2 logs to DDOSPOT_LOG_DIR (/var/log/ddospot); these are the v1
	// paths T-Pot's compose still names (see its deploy profile).
	"ddospot": {
		"/opt/ddospot/ddospot/logs": "v1 path",
		"/opt/ddospot/ddospot/bl":   "v1 path",
		"/opt/ddospot/ddospot/db":   "v1 path",
	},
}

// Honeypot containers have a read-only root, so every folder T-Pot's own
// compose (docker/<name>/docker-compose.yml) mounts for a honeypot is one the
// image writes to: without a QPot mount or tmpfs there, the write fails. That
// broke dionaea's malware capture, galah's TLS ports and every miniprint job.
func TestDeployCoversTPotWritablePaths(t *testing.T) {
	cfg := config.Default("tpot-paths")
	names := make([]string, 0, len(cfg.Honeypots))
	for n := range cfg.Honeypots {
		names = append(names, n)
	}
	sort.Strings(names)
	checked := 0
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("..", "..", "docker", n, "docker-compose.yml"))
		if err != nil {
			continue // no T-Pot reference (QPot's own services)
		}
		var doc struct {
			Services map[string]struct {
				Volumes []string `yaml:"volumes"`
				Tmpfs   []string `yaml:"tmpfs"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		s, ok := doc.Services[n]
		if !ok {
			continue
		}
		checked++
		var want []string
		for _, v := range s.Volumes {
			if i := strings.Index(v, ":/"); i >= 0 {
				p, _, _ := strings.Cut(v[i+1:], ":")
				want = append(want, strings.TrimSuffix(p, "/"))
			}
		}
		for _, v := range s.Tmpfs {
			p, _, _ := strings.Cut(v, ":")
			want = append(want, strings.TrimSuffix(p, "/"))
		}
		d := deployProfile(cfg, n)
		var have []string
		for _, v := range d.Volumes {
			if !v.ReadOnly {
				have = append(have, strings.TrimSuffix(v.ContainerPath, "/"))
			}
		}
		for _, tm := range d.Tmpfs {
			p, _, _ := strings.Cut(tm, ":")
			have = append(have, strings.TrimSuffix(p, "/"))
		}
		for _, p := range want {
			if _, ok := tpotPathExceptions[n][p]; ok {
				continue
			}
			covered := false
			for _, h := range have {
				if p == h || strings.HasPrefix(p, h+"/") {
					covered = true
				}
			}
			if !covered {
				t.Errorf("%s writes %s (T-Pot mounts it) but QPot gives it no writable mount; has %v", n, p, have)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("compared only %d honeypots with T-Pot's reference composes", checked)
	}
}

// dionaea's folders under /opt/dionaea/var/dionaea are made inside its data
// mount before start, or it finds no FTP root and no binaries folder.
func TestDionaeaDataFoldersAreMade(t *testing.T) {
	d := deployProfile(config.Default("dionaea-data"), "dionaea")
	mounted := false
	for _, v := range d.Volumes {
		if v.HostSubdir == "data" && v.ContainerPath == "/opt/dionaea/var/dionaea" && !v.ReadOnly {
			mounted = true
		}
	}
	if !mounted {
		t.Error("dionaea's data folder is not mounted writable")
	}
	for _, p := range []string{"binaries", "roots/ftp", "roots/tftp", "roots/www", "roots/upnp", "rtp"} {
		if !slices.Contains(d.ContainerDirs, "data/"+p) {
			t.Errorf("dionaea's %s folder is not made", p)
		}
	}
}

// No mount lies inside one the container writes to. The container could swap
// the inner folder for a symlink, and Docker follows a symlinked mount source
// on the next start, mounting whatever host folder it names (T-Pot nests
// dionaea's binaries, rtp and roots/* in its data mount this way). Folders an
// image needs there are made inside the volume instead (ContainerDirs).
func TestNoMountInsideAWritableMount(t *testing.T) {
	cfg := config.Default("nested-mounts")
	compared := 0
	for name := range cfg.Honeypots {
		d := deployProfile(cfg, name)
		for _, w := range d.Volumes {
			if w.ReadOnly || w.File {
				continue
			}
			for _, v := range d.Volumes {
				compared++
				if strings.HasPrefix(v.HostSubdir, w.HostSubdir+"/") {
					t.Errorf("%s: %s is mounted from inside the writable %s", name, v.HostSubdir, w.HostSubdir)
				}
				if strings.HasPrefix(v.ContainerPath, strings.TrimSuffix(w.ContainerPath, "/")+"/") {
					t.Errorf("%s: %s is mounted inside the writable %s", name, v.ContainerPath, w.ContainerPath)
				}
			}
		}
		for _, c := range d.ContainerDirs {
			vol, _, _ := strings.Cut(c, "/")
			if !slices.ContainsFunc(d.Volumes, func(v deployVolume) bool {
				return v.HostSubdir == vol && !v.ReadOnly && !v.File
			}) || !strings.Contains(c, "/") {
				t.Errorf("%s: folder %s is not inside one of its writable volumes", name, c)
			}
		}
	}
	if compared < 50 {
		t.Fatalf("compared only %d volume pairs", compared)
	}
}
