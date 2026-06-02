package intelligence

import (
	"fmt"
	"net"
	"regexp"
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
)

// pre-compiled patterns for IOC extraction.
var (
	reURL    = regexp.MustCompile(`https?://[^\s"']+|ftp://[^\s"']+`)
	reMD5    = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	reSHA1   = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reSHA256 = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reSHA512 = regexp.MustCompile(`\b[0-9a-fA-F]{128}\b`)
	// reDomain must accept every scheme reURL does (incl. ftp), otherwise
	// ftp:// downloads — a common ingress-tool-transfer pattern — yield a URL
	// IOC but never a domain IOC.
	reDomain = regexp.MustCompile(`(?i)(?:https?|ftp)://([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)`)
)

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
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, network)
		}
	}
}

// isPrivateIP returns true if ip is a loopback or RFC1918 address.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // treat unparseable as private to avoid false positives
	}
	for _, network := range privateNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

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

	// Source IP
	if event.SourceIP != "" && !isPrivateIP(event.SourceIP) {
		iocs = append(iocs, makeIOC(IOCTypeIP, event.SourceIP))
	}

	// Credential pair
	if event.Username != "" && event.Password != "" {
		cred := event.Username + ":" + event.Password
		iocs = append(iocs, makeIOC(IOCTypeCredential, cred))
	}

	// URLs from command
	if event.Command != "" {
		for _, u := range reURL.FindAllString(event.Command, -1) {
			u = trimURL(u)
			if u == "" {
				continue
			}
			iocs = append(iocs, makeIOC(IOCTypeURL, u))

			// Extract the host from the URL. reDomain's character class also
			// matches dotted-decimal IPv4 literals (e.g. http://203.0.113.9/x),
			// so an IP-literal host would otherwise be mistyped as a domain.
			// Classify it as an IP IOC instead - that is what it is, and it
			// keeps the blocklist/correlation by-type correct.
			if matches := reDomain.FindStringSubmatch(u); len(matches) > 1 {
				host := strings.ToLower(matches[1])
				if net.ParseIP(host) != nil {
					iocs = append(iocs, makeIOC(IOCTypeIP, host))
				} else {
					iocs = append(iocs, makeIOC(IOCTypeDomain, host))
				}
			}
		}

		// File hashes — longest first (SHA512, then SHA256, SHA1, MD5) to avoid
		// sub-matching. The \b anchors already make the lengths disjoint, but the
		// order + de-dup set keeps it robust. SHA-512 is increasingly the hash
		// threat-intel feeds and `sha512sum`-based droppers use to identify
		// payloads, so capturing it makes the IOC set usable against those feeds.
		seen := make(map[string]bool)
		for _, h := range reSHA512.FindAllString(event.Command, -1) {
			h = strings.ToLower(h)
			if !seen[h] {
				seen[h] = true
				iocs = append(iocs, makeIOC(IOCTypeHash, h))
			}
		}
		for _, h := range reSHA256.FindAllString(event.Command, -1) {
			h = strings.ToLower(h)
			if !seen[h] {
				seen[h] = true
				iocs = append(iocs, makeIOC(IOCTypeHash, h))
			}
		}
		for _, h := range reSHA1.FindAllString(event.Command, -1) {
			h = strings.ToLower(h)
			if !seen[h] {
				seen[h] = true
				iocs = append(iocs, makeIOC(IOCTypeHash, h))
			}
		}
		for _, h := range reMD5.FindAllString(event.Command, -1) {
			h = strings.ToLower(h)
			if !seen[h] {
				seen[h] = true
				iocs = append(iocs, makeIOC(IOCTypeHash, h))
			}
		}

		// Interesting commands. Trim BEFORE the length check: a whitespace-only
		// command (e.g. "    ") has byte length > 3 but trims to empty, which
		// would otherwise produce an empty-value IOC (found by FuzzExtract).
		if event.EventType == "command" {
			cleaned := strings.ToLower(strings.TrimSpace(event.Command))
			if len(cleaned) > 3 {
				iocs = append(iocs, makeIOC(IOCTypeCommand, cleaned))
			}
		}
	}

	// User agent from metadata
	if event.Metadata != nil {
		if ua, ok := event.Metadata["user_agent"]; ok && ua != "" {
			iocs = append(iocs, makeIOC(IOCTypeUserAgent, ua))
		}
	}

	return iocs
}
