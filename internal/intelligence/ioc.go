package intelligence

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// IOC type constants.
const (
	IOCTypeIP        = "ip"
	IOCTypeCredential = "credential"
	IOCTypeURL       = "url"
	IOCTypeHash      = "hash"
	IOCTypeCommand   = "command"
	IOCTypeUserAgent = "user_agent"
	IOCTypeDomain    = "domain"
)

// pre-compiled patterns for IOC extraction.
var (
	reURL      = regexp.MustCompile(`https?://[^\s"']+|ftp://[^\s"']+`)
	reMD5      = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	reSHA1     = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reSHA256   = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reDomain   = regexp.MustCompile(`(?i)https?://([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)`)
)

// privateNets lists RFC1918 and loopback ranges used to skip private IPs.
var privateNets []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
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
			iocs = append(iocs, makeIOC(IOCTypeURL, u))

			// Extract domain from URL
			if matches := reDomain.FindStringSubmatch(u); len(matches) > 1 {
				domain := strings.ToLower(matches[1])
				iocs = append(iocs, makeIOC(IOCTypeDomain, domain))
			}
		}

		// File hashes — SHA256 first (superset of shorter), then SHA1, then MD5
		// to avoid sub-matching. We de-duplicate by length.
		seen := make(map[string]bool)
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

		// Interesting commands
		if event.EventType == "command" && len(event.Command) > 3 {
			cleaned := strings.ToLower(strings.TrimSpace(event.Command))
			iocs = append(iocs, makeIOC(IOCTypeCommand, cleaned))
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
