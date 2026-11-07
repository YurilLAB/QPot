package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// FuzzHoneypotSettingsPut sends arbitrary honeypot names, setting keys and
// values (and raw bodies) to PUT /api/honeypots/settings through the full
// middleware. Nothing may fail with a server error; a refused request leaves
// the config file as it was; an accepted one saves exactly the value sent,
// which never carries markup, quotes, spaces or control characters.
func FuzzHoneypotSettingsPut(f *testing.F) {
	for _, s := range []struct{ name, key, value, raw string }{
		{"cowrie", "persona", "rhel-9", ""},
		{"cowrie", "bait", "off", ""},
		{"cowrie", "persona_rotation", "007", ""},
		{"conpot", "template", "iccp", ""},
		{"ssh-proxy", "backends", "16", ""},
		{"galah", "llm_server_url", "http://10.0.0.5:11434/x?y=1", ""},
		{"galah", "llm_model", "hf.co/org/M-GGUF:Q4", ""},
		{"galah", "llm_api_key", "sk-abc_123", ""},
		{"galah", "llm_temperature", "0.5", ""},
		{"<script>", "persona", "x", ""},
		{"cowrie", "persona", "<img src=x>", ""},
		{"", "", "", `{"name":"cowrie","settings":{"bait":"off"},"x":1}`},
		{"", "", "", `{"name":"cowrie","settings":{"bait":"off"}}garbage`},
		{"", "", "", `{"name":"cowrie","settings":null}`},
	} {
		f.Add(s.name, s.key, s.value, s.raw)
	}
	a := newAPITestServer(f, "api-fuzz-set", func(c *config.Config) { c.EnableHoneypot("cowrie") })
	a.runner.running = true
	f.Fuzz(func(t *testing.T, name, key, value, raw string) {
		body := raw
		if body == "" {
			b, err := json.Marshal(map[string]any{"name": name, "settings": map[string]string{key: value}})
			if err != nil {
				return
			}
			body = string(b)
		}
		before := a.configFile(t)
		rec := a.do(http.MethodPut, "/api/honeypots/settings", body)
		after := a.configFile(t)
		if rec.Code >= 500 {
			t.Fatalf("PUT %q: %d %s", body, rec.Code, rec.Body.String())
		}
		if rec.Code != http.StatusOK {
			if !bytes.Equal(before, after) {
				t.Fatalf("refused PUT %q (%d) changed the config", body, rec.Code)
			}
			var e apiError
			if json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Error == "" {
				t.Fatalf("refusal is not an error object: %q", rec.Body.String())
			}
			return
		}
		if raw != "" {
			return
		}
		cfg, err := config.Parse(after, a.cfg.ConfigPath)
		if err != nil {
			t.Fatalf("saved config does not parse: %v", err)
		}
		hp, ok := cfg.GetHoneypotConfig(name)
		if !ok || hp.CustomConfig[key] != value {
			t.Fatalf("accepted %s %s=%q, saved %q", name, key, value, hp.CustomConfig[key])
		}
		if strings.ContainsAny(value, "<>\"'` \t\r\n\x00\x7f") {
			t.Fatalf("accepted %s %s=%q", name, key, value)
		}
	})
}
