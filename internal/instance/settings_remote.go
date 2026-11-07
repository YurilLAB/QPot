package instance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// The rules a settings change from the web UI must pass on top of
// ValidateSettings. The web UI is a weaker boundary than the host: whoever
// has the QPot ID can use it, but cannot read the config file. Two settings
// patterns would let such a caller reach further than the UI:
//
//  1. An endpoint paired with a stored secret. galah sends its llm_api_key to
//     the server in llm_server_url (or to its llm_provider's): pointing that
//     at a server of the caller's would hand them the operator's key. So a
//     change of where the key goes must carry the key again (or clear it).
//  2. An endpoint the honeypot connects to: a cloud metadata service or a
//     link-local address would make the honeypot container an SSRF probe
//     into the host's cloud credentials.
//
// The CLI does not apply these: it runs as the host user, who can read and
// edit the config file (and the key in it) anyway, and making the operator
// type the key again would only put it into shell history and ps.

// ErrSecretRequired: a change of where a stored secret is sent did not carry
// the secret again.
var ErrSecretRequired = errors.New("secret must be entered again")

// SecretRequiredError says which secret settings a change must carry again.
type SecretRequiredError struct {
	Honeypot string
	Changed  []string // the endpoint settings changed
	Secrets  []string // the secrets to enter again (or clear)
}

func (e *SecretRequiredError) Error() string {
	return fmt.Sprintf("%s: enter %s again when you change %s (the key is sent to that server), or send it empty to remove it",
		e.Honeypot, strings.Join(e.Secrets, ", "), strings.Join(e.Changed, ", "))
}

// Is matches ErrSecretRequired.
func (e *SecretRequiredError) Is(target error) bool { return target == ErrSecretRequired }

// secretBoundSettings returns, for a honeypot with secret settings, the
// settings that decide where those secrets are sent: its endpoints (url
// settings) and its LLM provider. Nil when it has no secret.
func secretBoundSettings(name string) (secrets, endpoints []string) {
	for _, key := range SettingKeys(name) {
		switch {
		case IsSecretSetting(key):
			secrets = append(secrets, key)
		case settingSpecs[key].kind == "url" || key == "llm_provider":
			endpoints = append(endpoints, key)
		}
	}
	if len(secrets) == 0 {
		return nil, nil
	}
	return secrets, endpoints
}

// LookupFunc resolves a host name to its addresses.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemLookup resolves with the host's resolver.
func SystemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// endpointLookupTimeout bounds the name lookup of one endpoint setting.
const endpointLookupTimeout = 5 * time.Second

// CheckRemoteSettings applies the web UI's rules to changes (already checked
// by ValidateSettings): a change of where a stored secret is sent carries the
// secret again or clears it, and no endpoint setting names a link-local or
// cloud metadata address, also through a host name that resolves to one.
// lookup resolves host names (nil: SystemLookup).
func CheckRemoteSettings(ctx context.Context, cfg *config.Config, name string, changes []SettingChange, lookup LookupFunc) error {
	hp, ok := cfg.GetHoneypotConfig(name)
	if !ok {
		return &SettingsError{Kind: ErrUnknownHoneypot, Msg: fmt.Sprintf("unknown honeypot %q", name)}
	}
	if lookup == nil {
		lookup = SystemLookup
	}
	sent := map[string]string{}
	for _, c := range changes {
		sent[c.Key] = c.Value
	}
	for _, c := range changes {
		if c.Value == "" || settingSpecs[c.Key].kind != "url" {
			continue
		}
		if err := CheckEndpoint(ctx, c.Value, lookup); err != nil {
			return &SettingsError{Kind: ErrInvalidSetting, Msg: fmt.Sprintf("%s: %s %v", name, c.Key, err), Err: err}
		}
	}

	secrets, endpoints := secretBoundSettings(name)
	var changed []string
	for _, key := range endpoints {
		if v, ok := sent[key]; ok && v != hp.CustomConfig[key] {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	var again []string
	for _, key := range secrets {
		if hp.CustomConfig[key] == "" {
			continue // nothing stored to take along
		}
		if _, ok := sent[key]; !ok {
			again = append(again, key)
		}
	}
	if len(again) > 0 {
		return &SecretRequiredError{Honeypot: name, Changed: changed, Secrets: again}
	}
	return nil
}

// metadataHosts are host names of cloud instance metadata services.
var metadataHosts = []string{
	"metadata", "metadata.google.internal", "metadata.goog", "metadata.azure.com",
	"instance-data", "instance-data.ec2.internal", "metadata.tencentyun.com", "metadata.platformequinix.com",
}

// blockedPrefixes are address ranges an endpoint setting may not reach:
// link-local (cloud metadata lives at 169.254.169.254 and fd00:ec2::254 on
// some clouds), "this network", multicast and the clouds' other metadata or
// host-agent addresses.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"169.254.0.0/16", "fe80::/10", // link-local
		"0.0.0.0/8", "::/128", // unspecified, "this network"
		"224.0.0.0/4", "ff00::/8", "255.255.255.255/32", // multicast, broadcast
		"100.100.100.200/32", // Alibaba Cloud metadata
		"168.63.129.16/32",   // Azure host agent (WireServer)
		"fd00:ec2::254/128",  // AWS metadata over IPv6
		"192.0.0.192/32",     // Oracle Cloud metadata (legacy)
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// blockedAddr reports whether an endpoint may not reach a.
func blockedAddr(a netip.Addr) bool {
	// A zone (fe80::1%eth0) would make every Prefix.Contains false.
	a = a.Unmap().WithZone("")
	if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// dnsNameRe is a host name whose last label starts with a letter, so that
// numeric spellings of an address (2852039166, 0xa9.0xfe.0xa9.0xfe, 0251.0376)
// that some resolvers turn into 169.254.169.254 are never taken as names.
var dnsNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// CheckEndpoint reports whether a URL may be an endpoint setting: http or
// https, a host and no user name, and neither the host nor any address it
// resolves to now is link-local, a cloud metadata service, unspecified or
// multicast. Loopback and private addresses (a local Ollama) are allowed.
// A name can resolve differently later (DNS rebinding); this is a check at
// the time of the change.
func CheckEndpoint(ctx context.Context, raw string, lookup LookupFunc) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return errors.New("must be an http:// or https:// URL with a host and no user name")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return errors.New("must name a host")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if blockedAddr(a) {
			return errors.New("must not point at a link-local or cloud metadata address")
		}
		return nil
	}
	if strings.Contains(host, ":") || strings.Contains(host, "%") {
		return errors.New("has an address that is not valid")
	}
	if !dnsNameRe.MatchString(host) {
		return errors.New("has a host that is neither an IP address nor a host name")
	}
	if slices.Contains(metadataHosts, host) || strings.HasSuffix(host, ".metadata.google.internal") {
		return errors.New("must not point at a cloud metadata service")
	}
	lctx, cancel := context.WithTimeout(ctx, endpointLookupTimeout)
	defer cancel()
	addrs, err := lookup(lctx, host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("names a host that does not resolve from this computer (%s); use its IP address", host)
	}
	for _, a := range addrs {
		if blockedAddr(a) {
			return fmt.Errorf("names a host (%s) that resolves to a link-local or cloud metadata address", host)
		}
	}
	return nil
}
