package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

const galahTestKey = "sk-" + "storedKEY12345"

func newGalahServer(t *testing.T, name string, custom map[string]string) *apiTestServer {
	t.Helper()
	return newAPITestServer(t, name, func(c *config.Config) {
		c.EnableHoneypot("galah")
		c.SetHoneypotCustomConfig("galah", custom)
	})
}

func galahStored(t *testing.T, a *apiTestServer) map[string]string {
	t.Helper()
	cfg, err := config.Parse(a.configFile(t), a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	hp, _ := cfg.GetHoneypotConfig("galah")
	return hp.CustomConfig
}

func storedGalah() map[string]string {
	return map[string]string{"llm_provider": "openai", "llm_model": "gpt-4o-mini", "llm_api_key": galahTestKey,
		"llm_server_url": "https://llm.example.net"}
}

// An LLM API key goes to the server galah talks to: a web caller must not be
// able to point galah at a server of theirs and keep the operator's key.
func TestSettingsPutEndpointNeedsKeyAgain(t *testing.T) {
	a := newGalahServer(t, "api-set-keyagain", storedGalah())
	for _, body := range []string{
		`{"name":"galah","settings":{"llm_server_url":"http://203.0.113.9:8080"}}`,
		`{"name":"galah","settings":{"llm_server_url":""}}`,
		`{"name":"galah","settings":{"llm_provider":"ollama"}}`,
		`{"name":"galah","settings":{"llm_provider":"ollama","llm_model":"llama3.1"}}`,
	} {
		rec := a.do(http.MethodPut, "/api/honeypots/settings", body)
		e := decodeAPIError(t, rec)
		if rec.Code != http.StatusBadRequest || e.Code != "QP-INPUT-012" || len(e.Needs) != 1 || e.Needs[0] != "llm_api_key" ||
			!strings.Contains(e.Error, "llm_api_key again") {
			t.Errorf("%s without the key: %d %s", body, rec.Code, rec.Body.String())
		}
		if got := galahStored(t, a); got["llm_api_key"] != galahTestKey || got["llm_server_url"] != "https://llm.example.net" || got["llm_provider"] != "openai" {
			t.Fatalf("%s changed the stored settings: %v", body, got)
		}
		if strings.Contains(rec.Body.String(), galahTestKey) {
			t.Fatalf("refusal carries the key: %s", rec.Body.String())
		}
	}
	if len(a.runner.started) != 0 {
		t.Fatalf("galah recreated on a refused change: %v", a.runner.started)
	}

	// Not a change of where the key goes: the same URL, or the model alone.
	for _, body := range []string{
		`{"name":"galah","settings":{"llm_server_url":"https://llm.example.net"}}`,
		`{"name":"galah","settings":{"llm_model":"gpt-4o"}}`,
	} {
		if rec := a.do(http.MethodPut, "/api/honeypots/settings", body); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), galahTestKey) {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestSettingsPutEndpointWithKey(t *testing.T) {
	a := newGalahServer(t, "api-set-withkey", storedGalah())
	newKey := "sk-" + "newKEY67890"
	rec := a.do(http.MethodPut, "/api/honeypots/settings",
		`{"name":"galah","settings":{"llm_server_url":"http://ollama.lan:11434","llm_api_key":"`+newKey+`"}}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), newKey) || strings.Contains(rec.Body.String(), galahTestKey) {
		t.Fatalf("change with the key: %d %s", rec.Code, rec.Body.String())
	}
	if got := galahStored(t, a); got["llm_api_key"] != newKey || got["llm_server_url"] != "http://ollama.lan:11434" {
		t.Fatalf("stored: %v", got)
	}
	var resp settingsChangeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, si := range resp.Settings {
		if si.Key == "llm_api_key" && (si.Value != "" || !si.Set) {
			t.Fatalf("key setting in the answer: %+v", si)
		}
	}
	if rec := a.do(http.MethodGet, "/api/honeypots/settings?name=galah", ""); strings.Contains(rec.Body.String(), newKey) {
		t.Fatal("GET returns the key")
	}
}

func TestSettingsPutEndpointClearKey(t *testing.T) {
	a := newGalahServer(t, "api-set-clearkey", storedGalah())
	rec := a.do(http.MethodPut, "/api/honeypots/settings",
		`{"name":"galah","settings":{"llm_server_url":"http://10.0.0.5:11434","llm_provider":"ollama","llm_api_key":""}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("change clearing the key: %d %s", rec.Code, rec.Body.String())
	}
	if got := galahStored(t, a); got["llm_api_key"] != "" || got["llm_server_url"] != "http://10.0.0.5:11434" {
		t.Fatalf("stored: %v", got)
	}
	// With no key stored, nothing has to be entered again.
	if rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"galah","settings":{"llm_server_url":"http://192.168.1.20:11434"}}`); rec.Code != http.StatusOK {
		t.Fatalf("change without a stored key: %d %s", rec.Code, rec.Body.String())
	}
}

// Endpoint settings may not reach link-local or cloud metadata addresses,
// written as an address or as a host name that resolves to one. Loopback
// and private addresses (a local Ollama) are fine.
func TestSettingsPutEndpointRefusesMetadata(t *testing.T) {
	a := newAPITestServer(t, "api-set-meta", func(c *config.Config) { c.EnableHoneypot("beelzebub") })
	refused := []string{
		"http://169.254.169.254/latest/meta-data/", "http://169.254.170.2/v2/credentials", "http://[fe80::1]:11434",
		"http://[fe80::1%25eth0]:11434", "http://[fd00:ec2::254]/", "http://100.100.100.200/", "http://168.63.129.16/",
		"http://[::ffff:169.254.169.254]/", "http://0.0.0.0:11434", "http://224.0.0.1/",
		"http://metadata.google.internal/computeMetadata/v1/", "http://METADATA.GOOGLE.INTERNAL./", "http://metadata/",
		"http://meta.evil.test:11434", "http://v6meta.evil.test/", "http://mapped.evil.test/", "http://mixed.evil.test/",
		"http://2852039166/", "http://0xa9fea9fe/", "http://0251.0376.0251.0376/", "http://169.254.169.254.:80/",
		"http://unresolvable.invalid:11434",
	}
	for _, u := range refused {
		body := `{"name":"beelzebub","settings":{"llm_host":"` + u + `"}}`
		rec := a.do(http.MethodPut, "/api/honeypots/settings", body)
		if e := decodeAPIError(t, rec); rec.Code != http.StatusBadRequest || e.Code != "QP-INPUT-012" {
			t.Errorf("%s: %d %s", u, rec.Code, rec.Body.String())
		}
	}
	if hp, _ := a.s.config.GetHoneypotConfig("beelzebub"); hp.CustomConfig["llm_host"] != "" {
		t.Fatalf("a refused endpoint was stored: %v", hp.CustomConfig)
	}
	for _, u := range []string{"http://127.0.0.1:11434/api/chat", "http://localhost:11434/api/chat", "http://[::1]:11434/api/chat",
		"http://10.0.0.5:11434/api/chat", "http://192.168.1.20:11434/api/chat", "http://ollama.lan:11434/api/chat",
		"https://llm.example.net/v1/chat"} {
		rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"beelzebub","settings":{"llm_host":"`+u+`"}}`)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s", u, rec.Code, rec.Body.String())
		}
	}
}
