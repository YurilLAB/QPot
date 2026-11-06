package instance

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// adbBannerRe is the banner an Android 8 adbd sends: three properties without
// spaces around "=", then its feature list.
var adbBannerRe = regexp.MustCompile(`^device::ro\.product\.name=[^;= ]+;ro\.product\.model=[^;=]+;ro\.product\.device=[^;= ]+;features=cmd,stat_v2,shell_v2$`)

// adbhoneyConfigValues parses the [honeypot] section of an adbhoney.cfg.
func adbhoneyConfigValues(t *testing.T, cfg []byte) map[string][]string {
	t.Helper()
	vals := map[string][]string{}
	section := ""
	for _, ln := range strings.Split(string(cfg), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "[") {
			section = ln
			continue
		}
		if k, v, ok := strings.Cut(ln, " = "); ok && section == "[honeypot]" {
			vals[k] = append(vals[k], v)
		}
	}
	return vals
}

// TestAdbhoneyBanner guards the banner every ADB client receives: well formed,
// one device per instance, stable, and never the stock ADBHoney banner (whose
// "http://ro.product.name =starltexx" marks the honeypot).
func TestAdbhoneyBanner(t *testing.T) {
	seen := map[string]bool{}
	for i := range 300 {
		cfg := config.Default("adb-banner")
		cfg.QPotID = fmt.Sprintf("qp_adbbanner%06d", i)
		b := adbhoneyBanner(cfg)
		if !adbBannerRe.MatchString(b) {
			t.Fatalf("banner %q is not what adbd sends", b)
		}
		if b != adbhoneyBanner(cfg) {
			t.Fatal("banner is not stable for one instance")
		}
		for _, stock := range []string{"http://", "starltexx", "SM-G960F", " ="} {
			if strings.Contains(b, stock) {
				t.Fatalf("banner %q contains the stock %q", b, stock)
			}
		}
		seen[b] = true
	}
	if len(seen) != len(adbDevices) {
		t.Errorf("300 instances drew %d of %d devices", len(seen), len(adbDevices))
	}
}

// TestAdbhoneyConfig checks the config QPot mounts: the instance's banner,
// URL downloads off (the image's downloader fetches any URL from the
// honeypot's network), pushed files kept in dl/, logs where the collector
// reads them, and every key of the image's file.
func TestAdbhoneyConfig(t *testing.T) {
	cfg := config.Default("adb-config")
	cfg.QPotID = "qp_adbconfig0000000001"
	vals := adbhoneyConfigValues(t, adbhoneyConfig(cfg))
	want := map[string]string{
		"hostname": "honeypot01", "address": "0.0.0.0", "port": "5555",
		"http_download": "false", "http_timeout": "45",
		"download_dir": "dl/", "log_dir": "log/", "device_id": adbhoneyBanner(cfg),
	}
	for k, v := range want {
		if got := vals[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want [%q]", k, got, v)
		}
	}
	if len(vals) != len(want) {
		t.Errorf("[honeypot] has keys %v", vals)
	}
	for _, sec := range []string{"[output_log]", "[output_json]", "log_file = adbhoney.json"} {
		if !strings.Contains(string(adbhoneyConfig(cfg)), sec) {
			t.Errorf("config lacks %q", sec)
		}
	}
}

// TestAdbhoneyMounts: pushed files need a writable dl/ (on the read-only root
// every push broke off), and the config must be QPot's, read-only.
func TestAdbhoneyMounts(t *testing.T) {
	cfg := config.Default("adb-mounts")
	cfg.QPotID = "qp_adbmounts0000000001"
	hp := cfg.Honeypots["adbhoney"]
	hp.Enabled = true
	cfg.Honeypots["adbhoney"] = hp

	var dl, conf bool
	for _, v := range deployProfile(cfg, "adbhoney").Volumes {
		switch v.ContainerPath {
		case "/opt/adbhoney/dl":
			dl = v.HostSubdir == "dl" && !v.ReadOnly && !v.File
		case "/opt/adbhoney/_internal/adbhoney.cfg":
			conf = v.File && v.ReadOnly && string(v.Content) == string(adbhoneyConfig(cfg))
		}
	}
	if !dl || !conf {
		t.Fatalf("adbhoney volumes: dl=%v config=%v", dl, conf)
	}
	// The static profile has no content: only deployProfile knows the instance.
	for _, v := range deployProfileFor("adbhoney").Volumes {
		if v.File && len(v.Content) != 0 {
			t.Error("static adbhoney profile carries an instance's config")
		}
	}
	svc, tcp, _ := publishedPorts(t, cfg, "adbhoney")
	if len(tcp) != 1 || tcp[0] != 5555 {
		t.Errorf("adbhoney publishes %v", tcp)
	}
	for _, want := range []string{
		"/honeypots/adbhoney/dl:/opt/adbhoney/dl\n",
		"/honeypots/adbhoney/adbhoney.cfg:/opt/adbhoney/_internal/adbhoney.cfg:ro\n",
	} {
		if !strings.Contains(svc, want) {
			t.Errorf("adbhoney service lacks %q", strings.TrimSpace(want))
		}
	}
}
