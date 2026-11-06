package intelligence

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/qpot/qpot/internal/database"
)

// IOC type constants.
const (
	IOCTypeIP         = "ip"
	IOCTypeCredential = "credential"
	IOCTypeURL        = "url"
	IOCTypeHash       = "hash"
	IOCTypeCommand    = "command"
	IOCTypeUserAgent  = "user_agent"
	IOCTypeDomain     = "domain"
	IOCTypeWallet     = "wallet"
)

// pre-compiled patterns for IOC extraction.
var (
	// Any case: curl and wget accept HTTP:// as well, and refang turns
	// "HXXPS://" into "httPS://".
	reURL    = regexp.MustCompile(`(?i)(?:https?|ftp)://[^\s"']+`)
	reMD5    = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	reSHA1   = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reSHA256 = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reSHA512 = regexp.MustCompile(`\b[0-9a-fA-F]{128}\b`)
	// Cryptocurrency wallet addresses. Coinminer and ransomware payloads
	// dropped into honeypots routinely embed these (mining-pool wallets,
	// ransom-note addresses); extracting them lets the IOC set pivot on the
	// actor's wallet. reBTC is a CANDIDATE matcher only - every match is then
	// base58check-validated (validateBTCAddress) so random base58-looking
	// strings are rejected. ETH addresses are distinctive enough via the 0x
	// prefix + exactly-40-hex length (which also keeps them disjoint from the
	// bare-40-hex SHA-1 matcher, whose \b never fires after the "x").
	reBTC = regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)
	reETH = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)
	// reHostname is a DNS name with at least one dot, as found in a URL host.
	reHostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$`)
)

// urlHost returns the lower-cased host a URL found by reURL connects to, or
// "". The authority is split the way curl, wget and browsers do: it ends at
// the first '/', '?', '#' or '\', everything up to the last '@' is userinfo,
// then comes the host and an optional port, with an IPv6 literal in brackets.
// In "http://cdn.example.com@203.0.113.9/x" the host is 203.0.113.9.
func urlHost(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	auth := u[i+3:]
	if j := strings.IndexAny(auth, `/?#\`); j >= 0 {
		auth = auth[:j]
	}
	if j := strings.LastIndexByte(auth, '@'); j >= 0 {
		auth = auth[j+1:]
	}
	host := auth
	if strings.HasPrefix(host, "[") {
		j := strings.IndexByte(host, ']')
		if j < 0 {
			return ""
		}
		host = host[1:j]
	} else if j := strings.LastIndexByte(host, ':'); j >= 0 {
		host = host[:j]
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// hostIOC classifies a URL host as an IOC: (IOCTypeIP, address) for a public
// IP literal, (IOCTypeDomain, name) for a DNS name, or ("", "") for anything
// else (no host, a private or loopback address, an invalid name).
func hostIOC(host string) (string, string) {
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(host) {
			return "", ""
		}
		return IOCTypeIP, ip.String()
	}
	if v4, numeric := looseIPv4(host); numeric {
		if v4 == "" || isPrivateIP(v4) {
			return "", ""
		}
		return IOCTypeIP, v4
	}
	if reHostname.MatchString(host) {
		return IOCTypeDomain, host
	}
	return "", ""
}

// looseIPv4 reads a host whose last label is a number the way URL parsers
// (the WHATWG URL standard, curl, wget) do: up to four dot-separated parts,
// each decimal, 0x-hex or 0-octal, the last one filling the remaining bytes.
// "127.1", "0x7f.0.0.1", "0177.0.0.1" and "2130706433" are all 127.0.0.1.
// numeric reports whether the host ends in a number at all, in which case it
// is never a domain; addr is "" when it does but is not a valid address.
func looseIPv4(host string) (addr string, numeric bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if _, ok := ipv4Part(last); !ok && (last == "" || strings.Trim(last, "0123456789") != "") {
		return "", false
	}
	if len(parts) > 4 {
		return "", true
	}
	var n uint64
	for i, p := range parts {
		v, ok := ipv4Part(p)
		if !ok {
			return "", true
		}
		bits := uint(8)
		if i == len(parts)-1 {
			bits = 8 * uint(5-len(parts)) // the last part fills the rest
		}
		if v >= 1<<bits {
			return "", true
		}
		n = n<<bits | v
	}
	return fmt.Sprintf("%d.%d.%d.%d", n>>24, n>>16&255, n>>8&255, n&255), true
}

// ipv4Part parses one part of a loose IPv4 host: decimal, 0x-hex or 0-octal.
func ipv4Part(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		base, s = 16, s[2:]
	case len(s) >= 2 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return 0, true // "0x" alone is zero
	}
	v, err := strconv.ParseUint(s, base, 64)
	return v, err == nil
}

// urlTrailingCutset is stripped from the end of a URL extracted from a command
// line. The greedy [^\s"']+ class otherwise swallows trailing shell
// punctuation (e.g. "http://evil.com/x.sh;" or ".../a)"), which corrupts the
// URL IOC and defeats de-duplication because the same URL in different command
// contexts would produce different IOC values/IDs.
const urlTrailingCutset = ".,;:!?)]}>'\"|&"

// trimURL cleans a URL captured from a command line. A URL cannot contain
// whitespace or control characters, but the regex class [^\s"'] only excludes
// Go's ASCII \s ([\t\n\f\r ]) — it still admits vertical tab, NBSP and other
// Unicode whitespace/control runes. Cut at the first such rune, then strip
// trailing shell punctuation the greedy class over-captured.
func trimURL(u string) string {
	if i := strings.IndexFunc(u, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}); i >= 0 {
		u = u[:i]
	}
	return strings.TrimRight(u, urlTrailingCutset)
}

// reHxxp restores the defanged scheme (hxxp/hxxps, any case) to http/https.
// "hxxp" defangs "http" by replacing the "tt" with "xx", so map hxx -> htt and
// keep the trailing p / ps.
var reHxxp = regexp.MustCompile(`(?i)\bhxx(ps?://)`)

// defangReplacer restores the common bracketed/worded dot and separator
// defangs used by threat-intel and attacker notes. Order matters: longer,
// scheme-specific forms first.
var defangReplacer = strings.NewReplacer(
	"[://]", "://", "[:]", ":", "[//]", "//",
	"[.]", ".", "(.)", ".", "{.}", ".",
	"[dot]", ".", "(dot)", ".", "{dot}", ".",
	"[d0t]", ".", " dot ", ".", "[DOT]", ".",
	"[at]", "@", "(at)", "@",
)

// refang reverses common indicator defanging so IOCs embedded in dropped
// scripts, ransom notes or copied C2 are still extracted. It is applied only to
// a working copy fed to the indicator regexes - the original command text is
// preserved for the command IOC. Defanging conventions: CISA/MISP/STIX, e.g.
// hxxp://1.2.3[.]4/x, evil[dot]com, user[at]host.
func refang(s string) string {
	s = reHxxp.ReplaceAllString(s, "htt${1}")
	return defangReplacer.Replace(s)
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// validateBTCAddress reports whether s is a valid base58check Bitcoin address
// (legacy P2PKH/P2SH): a 25-byte decode of version(1) + hash160(20) +
// checksum(4), where the checksum is the first 4 bytes of double-SHA256 over
// the first 21 bytes. This rejects the random base58-looking strings reBTC
// would otherwise over-match, so a "wallet" IOC is only emitted for an address
// whose checksum actually verifies.
func validateBTCAddress(s string) bool {
	if len(s) < 26 || len(s) > 35 {
		return false
	}
	x := new(big.Int)
	base := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		d := strings.IndexByte(base58Alphabet, s[i])
		if d < 0 {
			return false
		}
		x.Mul(x, base)
		x.Add(x, big.NewInt(int64(d)))
	}
	dec := x.Bytes()
	// Leading '1' base58 digits encode leading zero bytes.
	nlz := 0
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		nlz++
	}
	full := append(make([]byte, nlz), dec...)
	if len(full) != 25 {
		return false
	}
	payload, checksum := full[:21], full[21:]
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	return bytes.Equal(h2[:4], checksum)
}

// privateNets lists RFC1918 and loopback ranges used to skip private IPs.
var privateNets []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"240.0.0.0/4",
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, network)
		}
	}
}

// isPrivateIP returns true if ip is not a routable attacker address: RFC1918,
// loopback, link-local, unique-local, unspecified (0.0.0.0 / ::, the
// collector's placeholder for "no source IP"), multicast, "this network"
// 0.0.0.0/8, carrier-grade NAT, and the reserved/broadcast 240.0.0.0/4.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // treat unparseable as private to avoid false positives
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, network := range privateNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// isCommandEvent reports whether an event records attacker shell input: the
// bare legacy "command" type or a honeypot's dotted name for it
// (cowrie.command.input, adbhoney.command, conpot.modbus.command, ...).
func isCommandEvent(eventType string) bool {
	return eventType == "command" || strings.Contains(eventType, ".command")
}

// maxIOCsPerType bounds how many IOCs of one type a single event yields. A
// dropper names a few dozen mirrors at most; without a bound one command full
// of URLs or hashes became that many IOC rows.
const maxIOCsPerType = 256

// Extractor extracts IOCs from honeypot events.
type Extractor struct{}

// NewExtractor creates a new Extractor.
func NewExtractor() *Extractor { return &Extractor{} }

// Extract pulls all IOCs from a single event. Returns zero or more IOCs.
func (e *Extractor) Extract(event *database.Event) []*database.IOC {
	now := time.Now().UTC()
	iocs := make([]*database.IOC, 0)

	makeIOC := func(iocType, value string) *database.IOC {
		return &database.IOC{
			ID:          fmt.Sprintf("%s:%s:%s", iocType, value, event.Honeypot),
			Type:        iocType,
			Value:       value,
			Honeypot:    event.Honeypot,
			SourceIP:    event.SourceIP,
			TechniqueID: event.TechniqueID,
			FirstSeen:   now,
			LastSeen:    now,
			Count:       1,
		}
	}

	// add records one indicator. An event names each indicator once however
	// often it repeats it (every IOC is one sighting, and the store adds
	// sightings up), and at most maxIOCsPerType of each type.
	seen := make(map[string]bool)
	perType := make(map[string]int)
	add := func(iocType, value string) {
		k := iocType + "\x00" + value
		if seen[k] || perType[iocType] >= maxIOCsPerType {
			return
		}
		seen[k] = true
		perType[iocType]++
		iocs = append(iocs, makeIOC(iocType, value))
	}

	// addURLs extracts URL IOCs (and their host as a domain/IP IOC) from text.
	addURLs := func(text string) {
		for _, u := range reURL.FindAllString(text, -1) {
			u = trimURL(u)
			if u == "" {
				continue
			}
			add(IOCTypeURL, u)

			// The host the URL connects to: an IP literal (e.g.
			// http://203.0.113.9/x) is an IP IOC, not a domain, which keeps the
			// blocklist/correlation by-type correct; a loopback/private literal
			// is not an indicator at all.
			if typ, v := hostIOC(urlHost(u)); typ != "" {
				add(typ, v)
			}
		}
	}

	// Source IP
	if event.SourceIP != "" && !isPrivateIP(event.SourceIP) {
		add(IOCTypeIP, event.SourceIP)
	}

	// Credential pair
	if event.Username != "" && event.Password != "" {
		add(IOCTypeCredential, event.Username+":"+event.Password)
	}

	// URLs from command
	if event.Command != "" {
		// Refang defanged indicators (hxxp://, 1.2.3[.]4, evil[dot]com) before
		// running the extractors, so IOCs embedded in dropped scripts, ransom
		// notes or copy-pasted C2 are captured. The de-fanged copy feeds only
		// the indicator regexes; the command IOC below keeps the original text.
		cmd := refang(event.Command)
		addURLs(cmd)

		// File hashes — longest first (SHA512, then SHA256, SHA1, MD5) to avoid
		// sub-matching. The \b anchors already make the lengths disjoint, but the
		// order + de-dup set keeps it robust. SHA-512 is increasingly the hash
		// threat-intel feeds and `sha512sum`-based droppers use to identify
		// payloads, so capturing it makes the IOC set usable against those feeds.
		for _, re := range []*regexp.Regexp{reSHA512, reSHA256, reSHA1, reMD5} {
			for _, h := range re.FindAllString(cmd, -1) {
				add(IOCTypeHash, strings.ToLower(h))
			}
		}

		// Cryptocurrency wallet addresses (coinminer/ransomware indicators).
		// BTC candidates are base58check-validated so only real addresses are
		// emitted; ETH addresses are kept as-is (lowercased for stable de-dup).
		for _, w := range reBTC.FindAllString(cmd, -1) {
			if !seen[IOCTypeWallet+"\x00"+w] && validateBTCAddress(w) {
				add(IOCTypeWallet, w)
			}
		}
		for _, w := range reETH.FindAllString(cmd, -1) {
			add(IOCTypeWallet, strings.ToLower(w))
		}

		// Interesting commands. Trim BEFORE the length check: a whitespace-only
		// command (e.g. "    ") has byte length > 3 but trims to empty, which
		// would otherwise produce an empty-value IOC (found by FuzzExtract).
		if isCommandEvent(event.EventType) {
			cleaned := strings.ToLower(strings.TrimSpace(event.Command))
			if len(cleaned) > 3 {
				add(IOCTypeCommand, cleaned)
			}
		}
	}

	// A payload that is a bare URL is a download location (cowrie/adbhoney
	// file_download events carry it there, not in the command).
	if p := strings.TrimSpace(string(event.Payload)); p != "" && !strings.ContainsAny(p, " \t\r\n") && reURL.MatchString(p) {
		addURLs(refang(p))
	}

	// Files an attacker downloaded or uploaded (cowrie/adbhoney
	// session.file_download / file_upload) carry the payload's SHA-256 in
	// metadata. Other events with a shasum (cowrie.log.closed: the TTY
	// recording) are not malware and are skipped.
	if event.Metadata != nil && (strings.Contains(event.EventType, "file_download") || strings.Contains(event.EventType, "file_upload")) {
		if h := strings.ToLower(event.Metadata["shasum"]); reSHA256.MatchString(h) && len(h) == 64 {
			add(IOCTypeHash, h)
		}
	}

	// User agent from metadata
	if event.Metadata != nil {
		if ua, ok := event.Metadata["user_agent"]; ok && ua != "" {
			add(IOCTypeUserAgent, ua)
		}
	}

	return iocs
}
