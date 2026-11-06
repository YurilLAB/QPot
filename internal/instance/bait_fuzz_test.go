package instance

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// FuzzCowrieBait drives the bait generator with any instance ID, persona,
// bait setting and canary.base_url (which the config does not validate). The
// plan must stay what qpot_bait.py reads (checkBaitPlan), the same for the same
// config, empty for a device persona or bait=off, and the healthcheck must
// ping either a clean http(s) base_url or the internal address.
func FuzzCowrieBait(f *testing.F) {
	f.Add("qp_fuzzbait0000000000000000", uint8(0), "", "")
	f.Add("qp_fuzzbait0000000000000001", uint8(3), "https://hc.example.net/", "on")
	f.Add("", uint8(7), "http://x/{{date:%Y}}", "off")
	f.Add("\x00\n{{host}}", uint8(200), "https://a.example", " off ")
	f.Add(strings.Repeat("q", 3000), uint8(12), "javascript:alert(1)", "")
	// hostile base_url on server personas with the bait on
	f.Add("qp_x", uint8(5), "https://u:p@h.example/c?x=1#y", "maybe")
	f.Add("qp_fuzzbait0000000000000002", uint8(4), "https://a.example\n PING=1", "")
	f.Add("qp_fuzzbait0000000000000003", uint8(1), "http://x/{{date:%Y}}", "on")
	f.Add("qp_fuzzbait0000000000000004", uint8(6), "https://h.example/$(id)", "")
	f.Add("qp_fuzzbait0000000000000005", uint8(2), "ftp://h.example", "")

	f.Fuzz(func(t *testing.T, id string, idx uint8, base, bait string) {
		p := tpotCowriePersonas[int(idx)%len(tpotCowriePersonas)]
		cfg := baitCfg(id, p.ID)
		cfg.Canary.BaseURL = base
		hp := cfg.Honeypots["cowrie"]
		hp.CustomConfig[baitSetting] = bait
		cfg.Honeypots["cowrie"] = hp

		plan, planted := cowrieBait(cfg)
		js := cowrieBaitJSON(cfg)
		if !bytes.Equal(js, cowrieBaitJSON(cfg)) {
			t.Fatal("the plan differs between two runs")
		}
		var back baitPlan
		if err := json.Unmarshal(js, &back); err != nil || back.Version != baitPlanVersion {
			t.Fatalf("plan JSON: %v", err)
		}
		if !p.Server || strings.TrimSpace(bait) == "off" {
			if len(plan.Files)+len(plan.Dirs)+len(plan.Links)+len(plan.Programs)+len(plan.Hosts) != 0 || len(planted) != 0 {
				t.Fatalf("%s (bait %q): bait planted", p.ID, bait)
			}
			return
		}
		checkBaitPlan(t, p, plan, planted)
		s := newBaitScene(cfg, p)
		if b := baitBeaconBase(base); b != "" {
			if s.pingURL != b+"/c/"+s.pingToken {
				t.Fatalf("base_url %q: ping URL %q", base, s.pingURL)
			}
		} else if s.pingURL != "http://"+s.monitor.IP+":8000/ping/"+s.pingToken {
			t.Fatalf("base_url %q refused, ping URL %q", base, s.pingURL)
		}
		if strings.ContainsAny(s.pingURL, " \t\n\r\"'$`{}\\") {
			t.Fatalf("ping URL %q would break the script", s.pingURL)
		}
		u, err := url.Parse(s.pingURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
			u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, "/"+s.pingToken) {
			t.Fatalf("ping URL %q is not a plain http(s) URL ending in the token", s.pingURL)
		}
	})
}
