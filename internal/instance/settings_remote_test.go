package instance

import (
	"context"
	"errors"
	"hash/fnv"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// fakeLookup resolves names for endpoint tests without the network.
func fakeLookup(_ context.Context, host string) ([]netip.Addr, error) {
	m := map[string][]string{
		"ollama.lan":       {"10.0.0.5"},
		"localhost":        {"127.0.0.1", "::1"},
		"meta.evil.test":   {"169.254.169.254"},
		"mixed.evil.test":  {"203.0.113.8", "169.254.170.2"},
		"mapped.evil.test": {"::ffff:169.254.169.254"},
		"zone.evil.test":   {"fe80::1%eth0"},
	}
	v, ok := m[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range v {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func TestCheckEndpoint(t *testing.T) {
	ctx := context.Background()
	for _, ok := range []string{
		"http://10.0.0.5:11434", "https://ollama.lan/api/chat", "http://localhost:11434", "http://127.0.0.1",
		"http://[::1]:11434", "http://192.168.0.2", "http://172.16.0.9:8080/x?y=1", "https://203.0.113.9",
	} {
		if err := CheckEndpoint(ctx, ok, fakeLookup); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://169.254.169.254", "http://169.254.0.1", "http://[fe80::1]", "http://[fe80::1%25eth0]",
		"http://[fd00:ec2::254]", "http://100.100.100.200", "http://168.63.129.16", "http://192.0.0.192",
		"http://[::ffff:169.254.169.254]", "http://[::ffff:a9fe:a9fe]", "http://[::ffff:100.100.100.200]", "http://[::ffff:168.63.129.16]", "http://0.0.0.0", "http://[::]", "http://0.1.2.3",
		"http://239.1.1.1", "http://[ff02::1]", "http://255.255.255.255",
		"http://metadata.google.internal", "http://Metadata.Google.Internal.", "http://metadata", "http://instance-data",
		"http://x.metadata.google.internal", "http://meta.evil.test", "http://mixed.evil.test", "http://mapped.evil.test",
		"http://zone.evil.test", "http://nosuch.invalid", "http://2852039166", "http://0xa9fea9fe", "http://0251.0376.0251.0376",
		"http://169.254.169", "http://0x7f.1", "ftp://10.0.0.5", "javascript:alert(1)", "http:///x", "http://u:p@10.0.0.5",
		"//10.0.0.5", "http:10.0.0.5", "http://exa_mple.lan", "http://-x.lan", "http://[fe80::1",
	} {
		if err := CheckEndpoint(ctx, bad, fakeLookup); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	// Numeric spellings of an address are never taken as names, nor are
	// metadata services reached by name, even where the resolver answers
	// every name (some resolvers read 2852039166 as 169.254.169.254).
	anything := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
	}
	for _, bad := range []string{"http://2852039166", "http://0xa9fea9fe", "http://0251.0376.0251.0376", "http://169.254.43518", "http://0x7f.1",
		"http://metadata.google.internal", "http://metadata", "http://a.metadata.google.internal", "http://instance-data"} {
		if err := CheckEndpoint(ctx, bad, anything); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := CheckEndpoint(ctx, "http://ollama.example", anything); err != nil {
		t.Errorf("a name was refused: %v", err)
	}
	// A lookup that hangs is cut off.
	slow := func(ctx context.Context, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }
	if err := CheckEndpoint(ctx, "http://slow.lan", slow); err == nil {
		t.Fatal("a name that never resolved was accepted")
	}
}

func TestCheckRemoteSettings(t *testing.T) {
	ctx := context.Background()
	cfg := settingsTestConfig(t, "remote-rules")
	key := "sk-" + "abc"
	cfg.SetHoneypotCustomConfig("galah", map[string]string{"llm_api_key": key, "llm_server_url": "http://10.0.0.5", "llm_provider": "openai"})

	cases := []struct {
		args []string
		want error
	}{
		{[]string{"llm_server_url=http://10.0.0.6"}, ErrSecretRequired},
		{[]string{"llm_server_url="}, ErrSecretRequired},
		{[]string{"llm_provider=ollama"}, ErrSecretRequired},
		{[]string{"llm_server_url=http://10.0.0.6", "llm_api_key=sk-new"}, nil},
		{[]string{"llm_server_url=http://10.0.0.6", "llm_api_key="}, nil},
		{[]string{"llm_server_url=http://10.0.0.5"}, nil}, // unchanged
		{[]string{"llm_model=m2", "llm_temperature=0.2"}, nil},
		{[]string{"llm_server_url=http://169.254.169.254", "llm_api_key=sk-new"}, ErrInvalidSetting},
		{[]string{"llm_server_url=http://meta.evil.test", "llm_api_key="}, ErrInvalidSetting},
	}
	for _, c := range cases {
		changes := ParseSettingArgs(c.args)
		if _, err := ValidateSettings(cfg, "galah", changes); err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		err := CheckRemoteSettings(ctx, cfg, "galah", changes, fakeLookup)
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%v: %v, want %v", c.args, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), key) {
			t.Errorf("%v: error carries the key: %v", c.args, err)
		}
	}
	var sre *SecretRequiredError
	err := CheckRemoteSettings(ctx, cfg, "galah", ParseSettingArgs([]string{"llm_server_url=http://10.0.0.7"}), fakeLookup)
	if !errors.As(err, &sre) || !slices.Equal(sre.Secrets, []string{"llm_api_key"}) || !slices.Equal(sre.Changed, []string{"llm_server_url"}) {
		t.Fatalf("SecretRequiredError: %#v", err)
	}

	// beelzebub has no stored secret: only the endpoint rule applies.
	if err := CheckRemoteSettings(ctx, cfg, "beelzebub", ParseSettingArgs([]string{"llm_host=http://10.0.0.9/api/chat"}), fakeLookup); err != nil {
		t.Fatal(err)
	}
	if err := CheckRemoteSettings(ctx, cfg, "beelzebub", ParseSettingArgs([]string{"llm_host=http://[fe80::2]/"}), fakeLookup); !errors.Is(err, ErrInvalidSetting) {
		t.Fatalf("link-local llm_host: %v", err)
	}
	if err := CheckRemoteSettings(ctx, cfg, "nosuch", nil, fakeLookup); !errors.Is(err, ErrUnknownHoneypot) {
		t.Fatalf("unknown honeypot: %v", err)
	}
}

// Every honeypot with a secret setting has its endpoints bound to it, and
// galah's are its server URL and provider.
func TestSecretBoundSettings(t *testing.T) {
	cfg := settingsTestConfig(t, "remote-bound")
	for name := range cfg.SnapshotHoneypots() {
		secrets, endpoints := secretBoundSettings(name)
		for _, key := range SettingKeys(name) {
			isEndpoint := settingSpecs[key].kind == "url" || key == "llm_provider"
			if len(secrets) > 0 && isEndpoint && !slices.Contains(endpoints, key) {
				t.Errorf("%s: endpoint %s not bound to its secrets", name, key)
			}
		}
	}
	s, e := secretBoundSettings("galah")
	if !slices.Equal(s, []string{"llm_api_key"}) || !slices.Equal(e, []string{"llm_provider", "llm_server_url"}) {
		t.Fatalf("galah: %v %v", s, e)
	}
	if s, e := secretBoundSettings("beelzebub"); s != nil || e != nil {
		t.Fatalf("beelzebub has no secret: %v %v", s, e)
	}
}

// FuzzCheckEndpoint: whatever CheckEndpoint accepts is an http(s) URL with a
// host and no user name, and neither that host nor what it resolves to is a
// blocked address. Names resolve to an address picked from the name, blocked
// ones included.
func FuzzCheckEndpoint(f *testing.F) {
	for _, s := range []string{"http://10.0.0.5:11434", "http://169.254.169.254", "http://[fe80::1%25x]", "http://2852039166",
		"http://metadata.google.internal", "https://a.b.c/", "http://[::ffff:a9fe:a9fe]", "http://x.lan.", "http://0xa9.0xfe.0xa9.0xfe"} {
		f.Add(s)
	}
	pool := []string{"10.1.2.3", "169.254.169.254", "fe80::5", "100.100.100.200", "8.8.8.8", "::ffff:169.254.1.1", "0.0.0.0", "224.0.0.9"}
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		h := fnv.New32a()
		h.Write([]byte(host))
		return []netip.Addr{netip.MustParseAddr(pool[h.Sum32()%uint32(len(pool))])}, nil
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if CheckEndpoint(context.Background(), raw, lookup) != nil {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
			t.Fatalf("accepted %q (%v)", raw, err)
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if a, err := netip.ParseAddr(host); err == nil {
			if blockedAddr(a) {
				t.Fatalf("accepted blocked address %q", raw)
			}
			return
		}
		last := host[strings.LastIndexByte(host, '.')+1:]
		if last == "" || last[0] < 'a' || last[0] > 'z' {
			t.Fatalf("accepted %q: host %q is not a name", raw, host)
		}
		addrs, _ := lookup(context.Background(), host)
		for _, a := range addrs {
			if blockedAddr(a) {
				t.Fatalf("accepted %q resolving to %s", raw, a)
			}
		}
	})
}
