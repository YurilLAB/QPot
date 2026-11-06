package instance

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
)

// TestDionaeaName: the machine name is one Windows 7 gives a computer
// (<USER>-PC, or WIN- and 11 characters for one set up from an image), a valid
// NetBIOS name, stable for an instance and spread across instances; never one
// of the names every install had.
func TestDionaeaName(t *testing.T) {
	shape := regexp.MustCompile(`^(WIN-[A-Z0-9]{11}|[A-Z]{3,12}-PC)$`)
	seen := map[string]bool{}
	win := 0
	for i := 0; i < 200; i++ {
		cfg := config.Default("dionaea-name")
		cfg.QPotID = "qp_" + strings.Repeat("ab", 8) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		name := dionaeaName(cfg)
		if !shape.MatchString(name) || len(name) > 15 || name == dionaeaStockName || name == "ADFS" {
			t.Fatalf("instance %d: name %q", i, name)
		}
		if dionaeaName(cfg) != name {
			t.Fatalf("instance %d: name not stable", i)
		}
		if strings.HasPrefix(name, "WIN-") {
			win++
		}
		seen[name] = true
	}
	if win < 40 || win > 120 || len(seen) < win+len(dionaeaUsers)/2 {
		t.Errorf("200 instances: %d WIN- names, %d distinct names", win, len(seen))
	}
}

// TestDionaeaPatchMounts: smb.yaml and each Python file that held a stock name
// are mounted read-only with the instance's name (and workgroup) in its place,
// and nothing else of them changes.
func TestDionaeaPatchMounts(t *testing.T) {
	cfg := config.Default("dionaea-patch")
	enableOnly(cfg, "dionaea")
	name := dionaeaName(cfg)
	python := map[string][]byte{
		dionaeaSource + "/smb/rpcservices.py":       dionaeaRPCServicesPy,
		dionaeaSource + "/smb/include/smbfields.py": dionaeaSMBFieldsPy,
		dionaeaSource + "/smb/extras.py":            dionaeaExtrasPy,
		dionaeaSource + "/mssql/include/tds.py":     dionaeaTDSPy,
	}
	smb := dionaeaEtc + "/services/smb.yaml"
	mounted := map[string]bool{}
	for _, v := range deployProfile(cfg, "dionaea").Volumes {
		if !strings.Contains(v.HostSubdir, "patch/") {
			continue
		}
		mounted[v.ContainerPath] = true
		if !v.File || !v.ReadOnly || len(v.Content) == 0 {
			t.Errorf("%s: file=%v ro=%v, %d bytes", v.ContainerPath, v.File, v.ReadOnly, len(v.Content))
		}
		if v.ContainerPath == smb {
			checkDionaeaSMB(t, v.Content, name)
			continue
		}
		original, ok := python[v.ContainerPath]
		if !ok {
			t.Errorf("unexpected patch mount %s", v.ContainerPath)
			continue
		}
		stock := bytes.Count(original, []byte(dionaeaStockName))
		if stock == 0 || bytes.Contains(v.Content, []byte(dionaeaStockName)) || bytes.Count(v.Content, []byte(name)) != stock {
			t.Errorf("%s: %d stock names in the image's file, %d left, %d of the instance's", v.ContainerPath,
				stock, bytes.Count(v.Content, []byte(dionaeaStockName)), bytes.Count(v.Content, []byte(name)))
		}
		if !bytes.Equal(bytes.ReplaceAll(v.Content, []byte(name), []byte(dionaeaStockName)), original) {
			t.Errorf("%s: more than the name changed", v.ContainerPath)
		}
	}
	for path := range python {
		if !mounted[path] {
			t.Errorf("%s is not mounted", path)
		}
	}
	if !mounted[smb] {
		t.Errorf("%s is not mounted", smb)
	}

	svc, _, _ := publishedPorts(t, cfg, "dionaea")
	for _, v := range dionaeaPatchVolumes(nil) {
		line := "/honeypots/dionaea/" + v.HostSubdir + ":" + v.ContainerPath + ":ro\n"
		if !strings.Contains(svc, line) {
			t.Errorf("dionaea service lacks %q", strings.TrimSpace(line))
		}
	}
	if cowriePatchVersion != TPotVersion {
		t.Error("dionaea's files were taken from the same image release as cowrie's; compare them again")
	}
}

// checkDionaeaSMB: the SMB service's config names the instance's machine in the
// default workgroup, and keeps everything else of the image's.
func checkDionaeaSMB(t *testing.T, content []byte, name string) {
	t.Helper()
	var services []struct {
		Name   string         `yaml:"name"`
		Config map[string]any `yaml:"config"`
	}
	if err := yaml.Unmarshal(content, &services); err != nil || len(services) != 1 {
		t.Fatalf("smb.yaml does not parse as one service: %v", err)
	}
	c := services[0].Config
	if c["server_name"] != name || c["primary_domain"] != dionaeaWorkgroup || c["oem_domain_name"] != dionaeaWorkgroup {
		t.Errorf("smb.yaml names %v in %v / %v", c["server_name"], c["primary_domain"], c["oem_domain_name"])
	}
	if c["os_type"] != 4 || c["native_os"] == nil || c["shares"] == nil {
		t.Errorf("smb.yaml lost the image's settings: %v", c)
	}
	if bytes.Contains(content, []byte("DACH")) || bytes.Contains(content, []byte("ADFS")) {
		t.Error("smb.yaml still names DACH or ADFS")
	}
	restored := content
	for _, line := range dionaeaSMBStock {
		key := line[1]
		value := map[string]string{"server_name": name}[key]
		if value == "" {
			value = dionaeaWorkgroup
		}
		restored = bytes.Replace(restored, []byte("    "+key+": "+value+"\n"), []byte(line[0]), 1)
	}
	if !bytes.Equal(restored, dionaeaSMBYaml) {
		t.Error("smb.yaml: more than the name and workgroup changed")
	}
}
