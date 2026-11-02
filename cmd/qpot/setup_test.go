package main

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func TestSetupProfilesAreKnownHoneypots(t *testing.T) {
	cfg := config.Default("profiles")
	for name, hps := range setupProfiles {
		for _, hp := range hps {
			if _, ok := cfg.Honeypots[hp]; !ok {
				t.Errorf("profile %s lists unknown honeypot %q", name, hp)
			}
		}
	}
}

func TestRenderServiceUnit(t *testing.T) {
	u := renderServiceUnit("/usr/local/bin/qpot", "/home/alice", "sensor1", "multi-user.target", true)
	for _, want := range []string{
		"ExecStart=/usr/local/bin/qpot up -i sensor1\n",
		"Environment=HOME=/home/alice\n",
		"After=network-online.target docker.service\n",
		"Restart=on-failure\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=full\n",
		"WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	user := renderServiceUnit("/home/alice/.local/bin/qpot", "/home/alice", "s", "default.target", false)
	if strings.Contains(user, "ProtectSystem") || !strings.Contains(user, "WantedBy=default.target") {
		t.Errorf("user unit:\n%s", user)
	}
}
